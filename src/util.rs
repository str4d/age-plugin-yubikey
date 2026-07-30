use std::fmt;
use std::iter;

use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use const_oid::ObjectIdentifier;
use x509_cert::der::Decode;
use yubikey::{
    piv::{RetiredSlotId, SlotId},
    Certificate, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::fl;
use crate::{error::Error, key::Stub, Recipient, BINARY_NAME, USABLE_SLOTS};

pub(crate) const POLICY_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

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
    let subject = cert.tbs_certificate().subject();

    // Look at Subject Organization to determine if we created this.
    match subject.organization().ok().flatten() {
        Some(org) if org.value() == BINARY_NAME => {
            // We store the identity name as a Common Name attribute.
            let name = subject
                .common_name()
                .ok()
                .flatten()
                .map(String::from)
                .unwrap_or_default(); // TODO: This should always be present.

            // We store the binary version as an Organizational Unit attribute.
            let version = subject
                .organization_unit()
                .ok()
                .flatten()
                .map(String::from)
                .unwrap_or_default(); // TODO: This should always be present.

            Some((name, Some(version)))
        }
        _ => {
            // Not one of ours, but we've already filtered for compatibility.
            if !all {
                return None;
            }

            // Display the entire subject.
            let name = subject.to_string();

            Some((name, None))
        }
    }
}

pub(crate) struct Metadata {
    serial: Serial,
    slot: RetiredSlotId,
    name: String,
    version: Option<String>,
    created: String,
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
                .extensions()
                .into_iter()
                .flatten()
                .find(|ext| ext.extn_id == POLICY_EXTENSION_OID)
                .filter(|policy| policy.extn_value.as_bytes().len() >= 2)
                .map(|policy| {
                    let value = policy.extn_value.as_bytes();
                    // We should only ever see one of three values for either policy, but
                    // handle unknown values just in case.
                    let pin_policy = match value[0] {
                        0x01 => Some(PinPolicy::Never),
                        0x02 => Some(PinPolicy::Once),
                        0x03 => Some(PinPolicy::Always),
                        _ => None,
                    };
                    let touch_policy = match value[1] {
                        0x01 => Some(TouchPolicy::Never),
                        0x02 => Some(TouchPolicy::Always),
                        0x03 => Some(TouchPolicy::Cached),
                        _ => None,
                    };
                    (pin_policy, touch_policy)
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
                pin_policy,
                touch_policy,
            })
    }

    /// Returns `true` if this identity was generated with an `age-plugin-yubikey` version
    /// before `p256tag` was added (and became the default).
    pub(crate) fn is_pre_p256tag(&self) -> bool {
        self.version
            .as_ref()
            .and_then(|version| version.split_once('.'))
            .and_then(|(major, rest)| rest.split_once('.').map(|(minor, _)| (major, minor)))
            .is_some_and(|(major, minor)| {
                // `p256tag` added in v0.6.0
                major == "0" && minor.parse::<u8>().is_ok_and(|minor| minor < 6)
            })
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
