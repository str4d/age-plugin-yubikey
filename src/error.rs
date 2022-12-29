use i18n_embed_fl::fl;
use std::fmt;
use std::io;
use yubikey::{piv::RetiredSlotId, Serial};

use crate::util::slot_to_ui;

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };
}

pub enum Error {
    CustomManagementKey,
    InvalidFlagCommand(String, String),
    InvalidFlagTui(String),
    InvalidPinLength,
    InvalidPinPolicy(String),
    InvalidSlot(u8),
    InvalidTouchPolicy(String),
    Io(io::Error),
    MultipleCommands,
    MultipleYubiKeys,
    NoEmptySlots(Serial),
    NoMatchingSerial(Serial),
    SlotHasNoIdentity(RetiredSlotId),
    SlotIsNotEmpty(RetiredSlotId),
    TimedOut,
    UseListForSingleSlot,
    YubiKey(yubikey::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<yubikey::Error> for Error {
    fn from(e: yubikey::Error) -> Self {
        Error::YubiKey(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CustomManagementKey => wlnfl!(f, "err-custom-mgmt-key")?,
            Error::InvalidFlagCommand(flag, command) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-invalid-flag-command",
                    flag = flag.as_str(),
                    command = command.as_str(),
                ),
            )?,
            Error::InvalidFlagTui(flag) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-invalid-flag-tui",
                    flag = flag.as_str(),
                ),
            )?,
            Error::InvalidPinLength => wlnfl!(f, "err-invalid-pin-length")?,
            Error::InvalidPinPolicy(s) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-invalid-pin-policy",
                    policy = s.as_str(),
                    expected = "always, once, never",
                ),
            )?,
            Error::InvalidSlot(slot) => writeln!(
                f,
                "{}",
                fl!(crate::LANGUAGE_LOADER, "err-invalid-slot", slot = slot),
            )?,
            Error::InvalidTouchPolicy(s) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-invalid-touch-policy",
                    policy = s.as_str(),
                    expected = "always, cached, never",
                ),
            )?,
            Error::Io(e) => writeln!(
                f,
                "{}",
                fl!(crate::LANGUAGE_LOADER, "err-io", err = e.to_string()),
            )?,
            Error::MultipleCommands => wlnfl!(f, "err-multiple-commands")?,
            Error::MultipleYubiKeys => wlnfl!(f, "err-multiple-yubikeys")?,
            Error::NoEmptySlots(serial) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-no-empty-slots",
                    serial = serial.to_string(),
                ),
            )?,
            Error::NoMatchingSerial(serial) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-no-matching-serial",
                    serial = serial.to_string(),
                ),
            )?,
            Error::SlotHasNoIdentity(slot) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-slot-has-no-identity",
                    slot = slot_to_ui(slot),
                ),
            )?,
            Error::SlotIsNotEmpty(slot) => writeln!(
                f,
                "{}",
                fl!(
                    crate::LANGUAGE_LOADER,
                    "err-slot-is-not-empty",
                    slot = slot_to_ui(slot),
                ),
            )?,
            Error::TimedOut => wlnfl!(f, "err-timed-out")?,
            Error::UseListForSingleSlot => wlnfl!(f, "err-use-list-for-single")?,
            Error::YubiKey(e) => match e {
                yubikey::Error::NotFound => wlnfl!(f, "err-yk-not-found")?,
                yubikey::Error::PcscError {
                    inner: Some(pcsc::Error::NoService),
                } => {
                    if cfg!(windows) {
                        wlnfl!(f, "err-yk-no-service-win")?;
                        let url = "https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-debugging-information#smart-card-service";
                        writeln!(
                            f,
                            "{}",
                            fl!(crate::LANGUAGE_LOADER, "rec-yk-no-service-win", url = url),
                        )?;
                    } else if cfg!(target_os = "macos") {
                        wlnfl!(f, "err-yk-no-service-macos")?;
                        let url = "https://apple.stackexchange.com/a/438198";
                        writeln!(
                            f,
                            "{}",
                            fl!(crate::LANGUAGE_LOADER, "rec-yk-no-service-macos", url = url),
                        )?;
                    } else {
                        wlnfl!(f, "err-yk-no-service-pcscd")?;
                        let apt = "sudo apt-get install pcscd";
                        writeln!(
                            f,
                            "{}",
                            fl!(crate::LANGUAGE_LOADER, "rec-yk-no-service-pcscd", apt = apt),
                        )?;
                    }
                }
                yubikey::Error::WrongPin { tries } => writeln!(
                    f,
                    "{}",
                    fl!(crate::LANGUAGE_LOADER, "err-yk-wrong-pin", tries = tries),
                )?,
                e => {
                    writeln!(
                        f,
                        "{}",
                        fl!(
                            crate::LANGUAGE_LOADER,
                            "err-yk-general",
                            err = e.to_string(),
                        ),
                    )?;
                    use std::error::Error;
                    if let Some(inner) = e.source() {
                        writeln!(
                            f,
                            "{}",
                            fl!(
                                crate::LANGUAGE_LOADER,
                                "err-yk-general-cause",
                                inner_err = inner.to_string(),
                            ),
                        )?;
                    }
                }
            },
        }
        writeln!(f)?;
        writeln!(f, "[ {} ]", crate::fl!("err-ux-A"))?;
        write!(
            f,
            "[ {}: https://str4d.xyz/age-plugin-yubikey/report {} ]",
            crate::fl!("err-ux-B"),
            crate::fl!("err-ux-C")
        )
    }
}
