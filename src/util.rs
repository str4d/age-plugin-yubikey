use std::fmt;
use std::iter;

use base64::{
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
    Engine,
};
use const_oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::{
    der::{
        self,
        asn1::OctetString,
        oid::db::rfc4519::{COMMON_NAME, ORGANIZATION_NAME},
        Decode,
    },
    ext::{Criticality, ToExtension},
};
use yubikey::{
    piv::{RetiredSlotId, SlotId},
    Certificate, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::fl;
use crate::native::p256tag;
use crate::native::x25519tag;
use crate::plugin::SupportedTag;
use crate::{error::Error, key::Stub, Recipient, BINARY_NAME, USABLE_SLOTS};

pub(crate) const POLICY_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
pub const ML_KEM_768_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55738.666.5");
const YUBIKEY_ATTESTATION: &str = "YubiKey PIV Attestation";

pub(crate) const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

pub(crate) fn ui_to_slot(slot: u8) -> Result<RetiredSlotId, Error> {
    // Use 1-indexing in the UI for niceness
    USABLE_SLOTS
        .get(slot as usize - 1)
        .cloned()
        .ok_or(Error::InvalidSlot(slot))
}

pub(crate) fn slot_to_ui(slot: &RetiredSlotId) -> u8 {
    // Use 1-indexing in the UI for niceness
    USABLE_SLOTS.iter().position(|s| s == slot).unwrap() as u8 + 1
}

pub(crate) struct UsagePolicies {
    pub(crate) pin: PinPolicy,
    pub(crate) touch: TouchPolicy,
}

impl AssociatedOid for UsagePolicies {
    const OID: ObjectIdentifier = POLICY_EXTENSION_OID;
}

impl der::Encode for UsagePolicies {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::new(2))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        encoder.write(&[self.pin.into(), self.touch.into()])
    }
}

impl<'a> der::Decode<'a> for UsagePolicies {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let pin = decoder
            .read_byte()?
            .try_into()
            .map_err(|_| decoder.error(der::ErrorKind::Failed))?;
        let touch = decoder
            .read_byte()?
            .try_into()
            .map_err(|_| decoder.error(der::ErrorKind::Failed))?;
        Ok(Self { pin, touch })
    }
}

impl ToExtension for UsagePolicies {
    type Error = der::Error;
    fn to_extension(
        self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> Result<x509_cert::ext::Extension, Self::Error> {
        let extn_value: &[u8; 21] = b"1.3.6.1.4.1.41482.3.8";
        Ok(x509_cert::ext::Extension {
            extn_id: POLICY_EXTENSION_OID,
            critical: false,
            extn_value: OctetString::new(*extn_value)?,
        })
    }
}

impl Criticality for UsagePolicies {
    fn criticality(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }
}

pub struct MlKem768Extension([u8; 32]);

impl MlKem768Extension {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_bytes(encoded: &[u8]) -> Self {
        let bytes: [u8; 32] = encoded.try_into().expect("secret length");
        Self(bytes)
    }
}

impl AssociatedOid for MlKem768Extension {
    const OID: ObjectIdentifier = ML_KEM_768_EXTENSION_OID;
}

impl der::Encode for MlKem768Extension {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let length: u32 = base64::encoded_len(32, true)
            .unwrap()
            .try_into()
            .expect("encoded length");
        Ok(der::Length::new(length))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let size: usize = base64::encoded_len(32, true).unwrap();
        let mut encoded_bytes: Vec<u8> = Vec::new();
        encoded_bytes.resize(size, 0);
        BASE64_STANDARD
            .encode_slice(self.0, &mut encoded_bytes)
            .expect("encoded seed");
        encoder.write(&encoded_bytes)
    }
}

impl<'a> der::Decode<'a> for MlKem768Extension {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let size: usize = base64::encoded_len(32, true).unwrap();
        let mut encoded_bytes: Vec<u8> = Vec::new();
        encoded_bytes.resize(size, 0);
        decoder.read_into(&mut encoded_bytes).expect("base64 read");

        let decoded_size = base64::decoded_len_estimate(size);
        let mut decoded_bytes: Vec<u8> = Vec::new();
        decoded_bytes.resize(decoded_size, 0);
        BASE64_STANDARD
            .decode_slice(encoded_bytes, &mut decoded_bytes)
            .map_err(|_| der::ErrorKind::Failed)?;
        let mut seed: [u8; 32] = [0; 32];
        seed.copy_from_slice(&decoded_bytes[..32]);
        Ok(Self(seed))
    }
}

impl ToExtension for MlKem768Extension {
    type Error = der::Error;
    fn to_extension(
        self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> Result<x509_cert::ext::Extension, Self::Error> {
        // TODO: https://github.com/RustCrypto/formats/issues/1490
        let extn_value: &[u8; 23] = b"1.3.6.1.4.1.55738.666.5";
        Ok(x509_cert::ext::Extension {
            extn_id: ML_KEM_768_EXTENSION_OID,
            critical: false,
            extn_value: OctetString::new(*extn_value)?,
        })
    }
}

impl Criticality for MlKem768Extension {
    fn criticality(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }
}

pub(crate) fn tag_from_string(s: String) -> Result<SupportedTag, Error> {
    match s.as_str() {
        "p256" => Ok(SupportedTag::P256Tag),
        "x25519" => Ok(SupportedTag::X25519Tag),
        "mlkem768x25519" => Ok(SupportedTag::MlKem768X25519Tag),
        _ => Err(Error::YubiKey(yubikey::Error::AlgorithmError)),
    }
}

pub(crate) fn pin_policy_from_string(s: String) -> Result<PinPolicy, Error> {
    match s.as_str() {
        "always" => Ok(PinPolicy::Always),
        "once" => Ok(PinPolicy::Once),
        "never" => Ok(PinPolicy::Never),
        _ => Err(Error::InvalidPinPolicy(s)),
    }
}

pub(crate) fn touch_policy_from_string(s: String) -> Result<TouchPolicy, Error> {
    match s.as_str() {
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        "never" => Ok(TouchPolicy::Never),
        _ => Err(Error::InvalidTouchPolicy(s)),
    }
}

pub(crate) fn pin_policy_to_str(policy: Option<PinPolicy>) -> String {
    match policy {
        Some(PinPolicy::Always) => fl!("pin-policy-always"),
        Some(PinPolicy::Once) => fl!("pin-policy-once"),
        Some(PinPolicy::Never) => fl!("pin-policy-never"),
        _ => fl!("unknown-policy"),
    }
}

pub(crate) fn touch_policy_to_str(policy: Option<TouchPolicy>) -> String {
    match policy {
        Some(TouchPolicy::Always) => fl!("touch-policy-always"),
        Some(TouchPolicy::Cached) => fl!("touch-policy-cached"),
        Some(TouchPolicy::Never) => fl!("touch-policy-never"),
        _ => fl!("unknown-policy"),
    }
}

const MODHEX: &str = "cbdefghijklnrtuv";
pub(crate) fn otp_serial_prefix(serial: Serial) -> String {
    iter::repeat(0)
        .take(4)
        .chain((0..8).rev().map(|i| (serial.0 >> (4 * i)) & 0x0f))
        .map(|i| MODHEX.char_indices().nth(i as usize).unwrap().1)
        .collect()
}

pub(crate) fn extract_name_and_version(
    cert: &x509_cert::Certificate,
    all: bool,
) -> Option<(String, Option<String>)> {
    // Look at Subject Organization to determine if we created this.
    match cert
        .tbs_certificate()
        .subject()
        .as_ref()
        .iter()
        .flat_map(|n| n.as_ref().iter().find(|a| a.oid == ORGANIZATION_NAME))
        .next()
    {
        Some(org) if org.value.decode_as::<String>().as_deref() == Ok(BINARY_NAME) => {
            // We store the identity name as a Common Name attribute.
            let name = cert
                .tbs_certificate()
                .subject()
                .as_ref()
                .iter()
                .flat_map(|n| n.as_ref().iter().find(|a| a.oid == COMMON_NAME))
                .next()
                .and_then(|cn| cn.value.decode_as::<String>().ok())
                .unwrap_or_default(); // TODO: This should always be present.

            // We store the binary version as an Organizational Unit attribute.
            let version = cert
                .tbs_certificate()
                .subject()
                .organization_unit()
                .and_then(|cn| Ok(cn.unwrap().value().to_string()))
                .map(|s| s.to_owned())
                .unwrap_or_default(); // TODO: This should always be present.

            Some((name, Some(version)))
        }
        _ => {
            match cert
                .tbs_certificate()
                .subject_public_key_info()
                .algorithm
                .oid
            {
                x25519tag::OID_X25519 => {
                    // Treat any YubiKey attested cert with an x25519 key as an age key.
                    let name = cert.tbs_certificate().subject().to_string();
                    if name.contains(YUBIKEY_ATTESTATION) {
                        // Need to return something for version
                        return Some((name, Some("".to_string())));
                    } else if !all {
                        return None;
                    }
                    Some((name, None))
                }
                _ => {
                    // Not one of ours, but we've already filtered for compatibility.
                    if !all {
                        return None;
                    }

                    // Display the entire subject.
                    let name = cert.tbs_certificate().subject().to_string();

                    Some((name, None))
                }
            }
        }
    }
}

pub(crate) struct Metadata {
    serial: Serial,
    slot: RetiredSlotId,
    name: String,
    version: Option<String>,
    created: String,
    pub(crate) algorithm: ObjectIdentifier,
    pub(crate) pin_policy: Option<PinPolicy>,
    pub(crate) touch_policy: Option<TouchPolicy>,
}

impl Metadata {
    pub(crate) fn extract(
        yubikey: &mut YubiKey,
        slot: RetiredSlotId,
        cert: &Certificate,
        all: bool,
    ) -> Option<Self> {
        // We store the PIN and touch policies for identities in their certificates
        // using the same certificate extension as PIV attestations.
        // https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
        let policies = |c: &x509_cert::Certificate| {
            c.tbs_certificate()
                .get_extension::<UsagePolicies>()
                .ok()
                .flatten()
                .map(|(_critical, policies)| {
                    // We should only ever see one of the three concrete values for either
                    // policy, but handle unknown values just in case.
                    (
                        match policies.pin {
                            PinPolicy::Default => None,
                            p => Some(p),
                        },
                        match policies.touch {
                            TouchPolicy::Default => None,
                            p => Some(p),
                        },
                    )
                })
                .unwrap_or((None, None))
        };

        extract_name_and_version(&cert.cert, all)
            .map(|(name, version)| {
                let (pin_policy, touch_policy) = if version.is_some() {
                    policies(&cert.cert)
                } else {
                    // We can extract the PIN and touch policies via an attestation. This
                    // is slow, but the user has asked for all compatible keys, so...
                    yubikey::piv::attest(yubikey, SlotId::Retired(slot))
                        .ok()
                        .and_then(|buf| {
                            x509_cert::Certificate::from_der(&buf)
                                .map(|c| policies(&c))
                                .ok()
                        })
                        .unwrap_or((None, None))
                };
                (name, version, pin_policy, touch_policy)
            })
            .map(|(name, version, pin_policy, touch_policy)| Metadata {
                serial: yubikey.serial(),
                slot,
                name,
                version,
                created: chrono::DateTime::<chrono::Utc>::from(
                    cert.cert
                        .tbs_certificate()
                        .validity()
                        .not_before
                        .to_system_time(),
                )
                .to_rfc2822(),
                algorithm: cert.subject_pki().algorithm.oid,
                pin_policy,
                touch_policy,
            })
    }

    /// Returns `true` if this identity was generated with an `age-plugin-yubikey` version
    /// before `p256tag` was added (and became the default).
    pub(crate) fn is_pre_native_tag(&self) -> bool {
        match self.algorithm {
            // Treat any x25519 key with YubiKey attested cert as legacy key
            x25519tag::OID_X25519 => self.name.contains(YUBIKEY_ATTESTATION),
            p256tag::OID_P256 => self
                .version
                .as_ref()
                .and_then(|version| version.split_once('.'))
                .and_then(|(major, rest)| rest.split_once('.').map(|(minor, _)| (major, minor)))
                .is_some_and(|(major, minor)| {
                    // `p256tag` added in v0.6.0
                    major == "0" && minor.parse::<u8>().is_ok_and(|minor| minor < 6)
                }),
            _ => false,
        }
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            fl!(
                "yubikey-metadata",
                serial = self.serial.to_string(),
                slot = slot_to_ui(&self.slot),
                name = self.name.as_str(),
                created = self.created.as_str(),
                pin_policy = pin_policy_to_str(self.pin_policy),
                touch_policy = touch_policy_to_str(self.touch_policy),
            )
        )
    }
}

pub(crate) fn print_identity(stub: Stub, recipient: Recipient, metadata: Metadata) {
    let legacy_recipient = recipient.legacy_recipient(&metadata);
    let recipient = recipient.to_string();
    if !console::user_attended() {
        let recipient = recipient.as_str();
        eprintln!("{}", fl!("print-recipient", recipient = recipient));
    }

    let identity = if let Some(legacy_recipient) = legacy_recipient {
        format!(
            "{}\n{stub}",
            fl!("yubikey-legacy-recipient", recipient = legacy_recipient),
        )
    } else {
        stub.to_string()
    };

    println!(
        "{}",
        fl!(
            "yubikey-identity",
            yubikey_metadata = metadata.to_string(),
            recipient = recipient,
            identity = identity,
        )
    );
}

pub(crate) fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
    if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
        return None;
    }

    BASE64_STANDARD_NO_PAD
        .decode_slice_unchecked(arg, buf.as_mut())
        .ok()
        .and_then(|len| (len == buf.as_mut().len()).then_some(buf))
}
