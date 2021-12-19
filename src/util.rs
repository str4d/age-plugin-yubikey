use std::fmt;

use x509_parser::{certificate::X509Certificate, der_parser::oid::Oid};
use yubikey::{
    piv::{RetiredSlotId, SlotId},
    PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::{error::Error, key::Stub, p256::Recipient, BINARY_NAME, USABLE_SLOTS};

pub(crate) const POLICY_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];

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

pub(crate) fn pin_policy_to_str(policy: Option<PinPolicy>) -> &'static str {
    match policy {
        Some(PinPolicy::Always) => "Always (A PIN is required for every decryption, if set)",
        Some(PinPolicy::Once) => "Once   (A PIN is required once per session, if set)",
        Some(PinPolicy::Never) => "Never  (A PIN is NOT required to decrypt)",
        _ => "Unknown",
    }
}

pub(crate) fn touch_policy_to_str(policy: Option<TouchPolicy>) -> &'static str {
    match policy {
        Some(TouchPolicy::Always) => "Always (A physical touch is required for every decryption)",
        Some(TouchPolicy::Cached) => {
            "Cached (A physical touch is required for decryption, and is cached for 15 seconds)"
        }
        Some(TouchPolicy::Never) => "Never  (A physical touch is NOT required to decrypt)",
        _ => "Unknown",
    }
}

pub(crate) fn extract_name(cert: &X509Certificate, all: bool) -> Option<(String, bool)> {
    // Look at Subject Organization to determine if we created this.
    match cert.subject().iter_organization().next() {
        Some(org) if org.as_str() == Ok(BINARY_NAME) => {
            // We store the identity name as a Common Name attribute.
            let name = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(|s| s.to_owned())
                .unwrap_or_default(); // TODO: This should always be present.

            Some((name, true))
        }
        _ => {
            // Not one of ours, but we've already filtered for compatibility.
            if !all {
                return None;
            }

            // Display the entire subject.
            let name = cert.subject().to_string();

            Some((name, false))
        }
    }
}

pub(crate) struct Metadata {
    serial: Serial,
    slot: RetiredSlotId,
    name: String,
    created: String,
    pub(crate) pin_policy: Option<PinPolicy>,
    pub(crate) touch_policy: Option<TouchPolicy>,
}

impl Metadata {
    pub(crate) fn extract(
        yubikey: &mut YubiKey,
        slot: RetiredSlotId,
        cert: &X509Certificate,
        all: bool,
    ) -> Option<Self> {
        // We store the PIN and touch policies for identities in their certificates
        // using the same certificate extension as PIV attestations.
        // https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
        let policies = |c: &X509Certificate| {
            c.tbs_certificate
                .find_extension(&Oid::from(POLICY_EXTENSION_OID).unwrap())
                // If the encoded extension doesn't have 2 bytes, we assume it is invalid.
                .filter(|policy| policy.value.len() >= 2)
                .map(|policy| {
                    // We should only ever see one of three values for either policy, but
                    // handle unknown values just in case.
                    let pin_policy = match policy.value[0] {
                        0x01 => Some(PinPolicy::Never),
                        0x02 => Some(PinPolicy::Once),
                        0x03 => Some(PinPolicy::Always),
                        _ => None,
                    };
                    let touch_policy = match policy.value[1] {
                        0x01 => Some(TouchPolicy::Never),
                        0x02 => Some(TouchPolicy::Always),
                        0x03 => Some(TouchPolicy::Cached),
                        _ => None,
                    };
                    (pin_policy, touch_policy)
                })
                .unwrap_or((None, None))
        };

        extract_name(cert, all)
            .map(|(name, ours)| {
                if ours {
                    let (pin_policy, touch_policy) = policies(cert);
                    (name, pin_policy, touch_policy)
                } else {
                    // We can extract the PIN and touch policies via an attestation. This
                    // is slow, but the user has asked for all compatible keys, so...
                    let (pin_policy, touch_policy) =
                        yubikey::piv::attest(yubikey, SlotId::Retired(slot))
                            .ok()
                            .and_then(|buf| {
                                x509_parser::parse_x509_certificate(&buf)
                                    .map(|(_, c)| policies(&c))
                                    .ok()
                            })
                            .unwrap_or((None, None));

                    (name, pin_policy, touch_policy)
                }
            })
            .map(|(name, pin_policy, touch_policy)| Metadata {
                serial: yubikey.serial(),
                slot,
                name,
                created: cert.validity().not_before.to_rfc2822(),
                pin_policy,
                touch_policy,
            })
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "#       Serial: {}, Slot: {}",
            self.serial,
            slot_to_ui(&self.slot)
        )?;
        writeln!(f, "#         Name: {}", self.name)?;
        writeln!(f, "#      Created: {}", self.created)?;
        writeln!(f, "#   PIN policy: {}", pin_policy_to_str(self.pin_policy))?;
        write!(
            f,
            "# Touch policy: {}",
            touch_policy_to_str(self.touch_policy)
        )
    }
}

pub(crate) fn print_identity(stub: Stub, recipient: Recipient, metadata: Metadata) {
    let recipient = recipient.to_string();
    if !console::user_attended() {
        eprintln!("Recipient: {}", recipient);
    }

    println!("{}", metadata);
    println!("#    Recipient: {}", recipient);
    println!("{}", stub.to_string());
}
