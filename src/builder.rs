use std::time::SystemTime;

use dialoguer::Password;
use rand::{rngs::OsRng, RngCore};
use x509_cert::{der::referenced::OwnedToRef, serial_number::SerialNumber, time::Validity};
use yubikey::{
    certificate::Certificate,
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    p256::Recipient,
    util::{Metadata, UsagePolicies},
    BINARY_NAME, USABLE_SLOTS,
};

pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub(crate) struct IdentityBuilder {
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
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
            AlgorithmId::EccP256,
            policies.pin,
            policies.touch,
        )?;

        // TODO: https://github.com/RustCrypto/formats/issues/1488
        // Document `OwnedToRef` usage in top-level docs somewhere (either of the
        // crate, or of `SubjectPublicKeyInfoOwned` so we know how to get a reference).
        let recipient = Recipient::from_spki(generated.owned_to_ref())
            .expect("YubiKey generates a valid pubkey");
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let serial = {
            // TODO: https://github.com/RustCrypto/formats/pull/1270
            // adds `SerialNumber::generate`; use it when available.
            let mut serial = [0; 20];
            OsRng.fill_bytes(&mut serial);
            SerialNumber::new(&serial).expect("valid")
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
        if let TouchPolicy::Never = policies.touch {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/581
        let cert = Certificate::generate_self_signed::<_, p256::NistP256>(
            yubikey,
            SlotId::Retired(slot),
            serial,
            Validity {
                not_before: SystemTime::now().try_into().map_err(Error::Build)?,
                not_after: x509_cert::time::Time::INFINITY,
            },
            // TODO: https://github.com/RustCrypto/formats/issues/1489
            format!("O={BINARY_NAME},OU={},CN={name}", env!("CARGO_PKG_VERSION"))
                .parse()
                .map_err(Error::Build)?,
            generated,
            // TODO: https://github.com/RustCrypto/formats/issues/1490
            // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/580
            |builder| {
                builder.add_extension(&policies).map_err(|e| match e {
                    x509_cert::builder::Error::Asn1(error) => error,
                    e => panic!("Cannot handle this error with the yubikey 0.8 crate: {e}"),
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
