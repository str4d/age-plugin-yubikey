use std::fmt;
use std::io;
use yubikey_piv::{key::RetiredSlotId, Serial};

use crate::util::slot_to_ui;

pub enum Error {
    CustomManagementKey,
    InvalidPinLength,
    InvalidPinPolicy(String),
    InvalidSlot(u8),
    InvalidTouchPolicy(String),
    Io(io::Error),
    MultipleCommands,
    MultipleIdentities,
    MultipleYubiKeys,
    NoEmptySlots(Serial),
    NoIdentities,
    NoMatchingSerial(Serial),
    SlotHasNoIdentity(RetiredSlotId),
    SlotIsNotEmpty(RetiredSlotId),
    TimedOut,
    YubiKey(yubikey_piv::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<yubikey_piv::error::Error> for Error {
    fn from(e: yubikey_piv::error::Error) -> Self {
        Error::YubiKey(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CustomManagementKey => {
                writeln!(f, "Custom unprotected management keys are not supported.")?
            }
            Error::InvalidPinLength => writeln!(f, "The PIN needs to be 1-8 characters.")?,
            Error::InvalidPinPolicy(s) => writeln!(
                f,
                "Invalid PIN policy '{}' (expected [always, once, never]).",
                s
            )?,
            Error::InvalidSlot(slot) => writeln!(
                f,
                "Invalid slot '{}' (expected number between 1 and 20).",
                slot
            )?,
            Error::InvalidTouchPolicy(s) => writeln!(
                f,
                "Invalid touch policy '{}' (expected [always, cached, never]).",
                s
            )?,
            Error::Io(e) => writeln!(f, "Failed to set up YubiKey: {}", e)?,
            Error::MultipleCommands => writeln!(
                f,
                "Only one of --generate, --identity, --list, --list-all can be specified."
            )?,
            Error::MultipleIdentities => writeln!(
                f,
                "This YubiKey has multiple age identities. Use --slot to select a single identity."
            )?,
            Error::MultipleYubiKeys => writeln!(
                f,
                "Multiple YubiKeys are plugged in. Use --serial to select a single YubiKey."
            )?,
            Error::NoEmptySlots(serial) => {
                writeln!(f, "YubiKey with serial {} has no empty slots.", serial)?
            }
            Error::NoIdentities => {
                writeln!(f, "This YubiKey does not contain any age identities.")?
            }
            Error::NoMatchingSerial(serial) => {
                writeln!(f, "Could not find YubiKey with serial {}.", serial)?
            }
            Error::SlotHasNoIdentity(slot) => writeln!(
                f,
                "Slot {} does not contain an age identity or compatible key.",
                slot_to_ui(slot)
            )?,
            Error::SlotIsNotEmpty(slot) => writeln!(
                f,
                "Slot {} is not empty. Use --force to overwrite the slot.",
                slot_to_ui(slot)
            )?,
            Error::TimedOut => {
                writeln!(f, "Timed out while waiting for a YubiKey to be inserted.")?
            }
            Error::YubiKey(e) => match e {
                yubikey_piv::error::Error::NotFound => {
                    writeln!(f, "Please insert the YubiKey you want to set up")?
                }
                yubikey_piv::error::Error::WrongPin { tries } => writeln!(
                    f,
                    "Invalid PIN ({} tries remaining before it is blocked)",
                    tries
                )?,
                e => {
                    writeln!(f, "Error while communicating with YubiKey: {}", e)?;
                    use std::error::Error;
                    if let Some(inner) = e.source() {
                        writeln!(f, "Cause: {}", inner)?;
                    }
                }
            },
        }
        writeln!(f)?;
        writeln!(
            f,
            "[ Did this not do what you expected? Could an error be more useful? ]"
        )?;
        write!(
            f,
            "[ Tell us: https://str4d.xyz/age-plugin-yubikey/report              ]"
        )
    }
}
