use std::fmt;
use std::io;
use yubikey_piv::{key::RetiredSlotId, Serial};

use crate::USABLE_SLOTS;

pub enum Error {
    InvalidSlot(u8),
    Io(io::Error),
    MultipleCommands,
    MultipleIdentities,
    MultipleYubiKeys,
    NoIdentities,
    NoMatchingSerial(Serial),
    SlotHasNoIdentity(RetiredSlotId),
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
            Error::InvalidSlot(slot) => writeln!(
                f,
                "Invalid slot '{}' (expected number between 1 and 20).",
                slot
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
            Error::NoIdentities => {
                writeln!(f, "This YubiKey does not contain any age identities.")?
            }
            Error::NoMatchingSerial(serial) => {
                writeln!(f, "Could not find YubiKey with serial {}.", serial)?
            }
            Error::SlotHasNoIdentity(slot) => writeln!(
                f,
                "Slot {} does not contain an age identity or compatible key.",
                USABLE_SLOTS.iter().position(|s| s == slot).unwrap() + 1
            )?,
            Error::TimedOut => {
                writeln!(f, "Timed out while waiting for a YubiKey to be inserted.")?
            }
            Error::YubiKey(e) => match e {
                yubikey_piv::error::Error::NotFound => {
                    writeln!(f, "Please insert the YubiKey you want to set up")?
                }
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
