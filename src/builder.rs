use std::time::SystemTime;

use dialoguer::Password;
use hpke::Kem;
use spki::{der::referenced::OwnedToRef, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    certificate::Rfc5280,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use yubikey::{
    certificate::{yubikey_signer, CertInfo, Certificate},
    piv::{generate as yubikey_generate, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    native::{mlkem768x25519tag, p256tag},
    plugin::SupportedTag,
    util::{Metadata, MlKem768Extension, UsagePolicies, OID_RSA},
    Recipient, BINARY_NAME, USABLE_SLOTS,
};

pub(crate) const DEFAULT_TAG: SupportedTag = SupportedTag::P256Tag;
pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

struct SelfSigned {
    subject: Name,
}

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        // RFC 5280 Section 3.2:
        //
        // > Self-issued certificates are CA certificates in which the issuer and subject
        // > are the same entity. [..] Self-signed certificates are self-issued
        // > certificates where the digital signature may be verified by the public key
        // > bound into the certificate.
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        Ok(vec![])
    }
}

pub(crate) struct IdentityBuilder {
    tag: Option<SupportedTag>,
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(tag: Option<SupportedTag>, slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            tag,
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let tag = self.tag.unwrap_or(DEFAULT_TAG);
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| !keys.iter().any(|key| key.slot() == SlotId::Retired(slot)))
                    .cloned()
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let policies = UsagePolicies {
            pin: self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY),
            touch: self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY),
        };

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            tag.algorithm(),
            policies.pin,
            policies.touch,
        )?;
        let generated_ref: SubjectPublicKeyInfoRef =
            SubjectPublicKeyInfoOwned::owned_to_ref(&generated);

        let recipient =
            Recipient::from_spki(generated_ref).expect("YubiKey generates a valid pubkey");
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let serial = {
            let mut csprng = rand::rng();
            SerialNumber::generate(&mut csprng)
        };

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = policies.pin {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }

        match tag {
            SupportedTag::X25519Tag | SupportedTag::MlKem768X25519Tag => {
                let keys = Key::list(yubikey)?;
                let sign_key = keys.iter().find(|p| p.slot() == SlotId::Signature);

                // Either use an available signing key or use the builtin YubiKey attestation to
                // generate a certificate since x25519 keys cannot sign for themselves.
                let cert = match sign_key {
                    Some(key) => {
                        let mut builder = CertificateBuilder::new(
                            SelfSigned {
                                subject: format!(
                                    "O={BINARY_NAME},OU={},CN={name}",
                                    env!("CARGO_PKG_VERSION")
                                )
                                .parse()
                                .map_err(Error::Build)?,
                            },
                            serial.clone(),
                            Validity::<Rfc5280>::new(
                                SystemTime::now().try_into().map_err(Error::Build)?,
                                x509_cert::time::Time::INFINITY,
                            ),
                            generated.clone(),
                        )
                        .unwrap();
                        builder
                            .add_extension(&policies)
                            .map_err(|e| match e {
                                e => panic!(
                                    "Cannot handle this error with the yubikey 0.8 crate: {e}"
                                ),
                            })
                            .unwrap();
                        if tag == SupportedTag::MlKem768X25519Tag {
                            let mut csprng = rand::rng();
                            let (dk, _ek) =
                                mlkem768x25519tag::MlKem768X25519::gen_keypair(&mut csprng);
                            let kem_policy = MlKem768Extension::from_bytes(dk.as_bytes());
                            builder
                                .add_extension(&kem_policy)
                                .map_err(|e| match e {
                                    _ => panic!("Cannot add ML-KEM seed to certificate"),
                                })
                                .unwrap();
                        }
                        // Match yubikey signer to signing key algorithm. Only supports RSA or P256
                        // without adding another external library.
                        let cert = match key.certificate().subject_pki().algorithm.oid {
                            OID_RSA => {
                                // Need to determine RSA key type. Uses less than comparison
                                // because key length includes header and length info in TLV.
                                let length =
                                    key.certificate().subject_pki().subject_public_key.bit_len();
                                if length < 2048 {
                                    let signer = yubikey_signer::Signer::<
                                        '_,
                                        yubikey_signer::YubiRsa<yubikey_signer::Rsa1024>,
                                    >::new(
                                        yubikey,
                                        key.slot(),
                                        key.certificate().subject_pki(),
                                    )?;
                                    builder.build(&signer).expect("signature")
                                } else if length < 3072 {
                                    let signer = yubikey_signer::Signer::<
                                        '_,
                                        yubikey_signer::YubiRsa<yubikey_signer::Rsa2048>,
                                    >::new(
                                        yubikey,
                                        key.slot(),
                                        key.certificate().subject_pki(),
                                    )?;
                                    builder.build(&signer).expect("signature")
                                } else if length < 4096 {
                                    let signer = yubikey_signer::Signer::<
                                        '_,
                                        yubikey_signer::YubiRsa<yubikey_signer::Rsa3072>,
                                    >::new(
                                        yubikey,
                                        key.slot(),
                                        key.certificate().subject_pki(),
                                    )?;
                                    builder.build(&signer).expect("signature")
                                } else {
                                    let signer = yubikey_signer::Signer::<
                                        '_,
                                        yubikey_signer::YubiRsa<yubikey_signer::Rsa4096>,
                                    >::new(
                                        yubikey,
                                        key.slot(),
                                        key.certificate().subject_pki(),
                                    )?;
                                    builder.build(&signer).expect("signature")
                                }
                            }
                            p256tag::OID_P256 => {
                                let signer = yubikey_signer::Signer::<'_, p256::NistP256>::new(
                                    yubikey,
                                    key.slot(),
                                    key.certificate().subject_pki(),
                                )?;
                                builder.build(&signer).expect("signature")
                            }
                            _ => panic!("No supported signing key available"),
                        };
                        let cert = Certificate { cert };
                        cert.write(yubikey, SlotId::Retired(slot), CertInfo::Uncompressed)
                            .unwrap();
                        cert
                    }
                    None => {
                        let buf = yubikey::piv::attest(yubikey, SlotId::Retired(slot))?;
                        let cert = Certificate::from_bytes(buf)?;
                        let _ = cert.write(yubikey, SlotId::Retired(slot), CertInfo::Uncompressed);
                        cert
                    }
                };
                let metadata = Metadata::extract(yubikey, slot, &cert, true).unwrap();

                match tag {
                    SupportedTag::MlKem768X25519Tag => {
                        let recipient = Recipient::from_certificate(&cert).unwrap();
                        Ok((
                            Stub::new(yubikey.serial(), slot, &recipient),
                            recipient,
                            metadata,
                        ))
                    }
                    _ => Ok((
                        Stub::new(yubikey.serial(), slot, &recipient),
                        recipient,
                        metadata,
                    )),
                }
            }
            SupportedTag::P256Tag => {
                if let TouchPolicy::Never = policies.touch {
                    // No need to touch YubiKey
                } else {
                    eprintln!("{}", fl!("builder-touch-yk"));
                }
                let cert = Certificate::generate_self_signed::<_, p256::NistP256>(
                    yubikey,
                    SlotId::Retired(slot),
                    serial,
                    Validity::new(
                        SystemTime::now().try_into().map_err(Error::Build)?,
                        x509_cert::time::Time::INFINITY,
                    ),
                    // TODO: https://github.com/RustCrypto/formats/issues/1489
                    format!("O={BINARY_NAME},OU={},CN={name}", env!("CARGO_PKG_VERSION"))
                        .parse()
                        .map_err(Error::Build)?,
                    generated,
                    |builder| {
                        builder.add_extension(&policies).map_err(|e| match e {
                            _ => panic!("Cannot handle this error with the yubikey 0.8 crate: {e}"),
                        })
                    },
                )?;

                let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

                Ok((
                    Stub::new(yubikey.serial(), slot, &recipient),
                    recipient,
                    metadata,
                ))
            }
        }
    }
}
