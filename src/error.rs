use std::fmt;
use std::io;
use yubikey::{piv::RetiredSlotId, Serial};

use crate::util::slot_to_ui;

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };
    ($f:ident, $message_id:literal, $($kwarg:expr),* $(,)*) => {{
        writeln!($f, "{}", $crate::fl!($message_id, $($kwarg,)*))
    }};
}

pub enum Error {
    CustomManagementKey,
    InvalidFlagCommand(String, String),
    InvalidFlagTui(String),
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
            Error::CustomManagementKey => {
                wlnfl!(f, "err-custom-mgmt-key")?;
                let cmd = "ykman piv access change-management-key --protect";
                let url = "https://developers.yubico.com/yubikey-manager/";
                wlnfl!(f, "rec-custom-mgmt-key", cmd = cmd, url = url)?;
            }
            Error::InvalidFlagCommand(flag, command) => wlnfl!(
                f,
                "err-invalid-flag-command",
                flag = flag.as_str(),
                command = command.as_str(),
            )?,
            Error::InvalidFlagTui(flag) => wlnfl!(f, "err-invalid-flag-tui", flag = flag.as_str())?,
            Error::InvalidPinPolicy(s) => wlnfl!(
                f,
                "err-invalid-pin-policy",
                policy = s.as_str(),
                expected = "always, once, never",
            )?,
            Error::InvalidSlot(slot) => wlnfl!(f, "err-invalid-slot", slot = slot)?,
            Error::InvalidTouchPolicy(s) => wlnfl!(
                f,
                "err-invalid-touch-policy",
                policy = s.as_str(),
                expected = "always, cached, never",
            )?,
            Error::Io(e) => wlnfl!(f, "err-io", err = e.to_string())?,
            Error::MultipleCommands => wlnfl!(f, "err-multiple-commands")?,
            Error::MultipleYubiKeys => wlnfl!(f, "err-multiple-yubikeys")?,
            Error::NoEmptySlots(serial) => {
                wlnfl!(f, "err-no-empty-slots", serial = serial.to_string())?
            }
            Error::NoMatchingSerial(serial) => {
                wlnfl!(f, "err-no-matching-serial", serial = serial.to_string())?
            }
            Error::SlotHasNoIdentity(slot) => {
                wlnfl!(f, "err-slot-has-no-identity", slot = slot_to_ui(slot))?
            }
            Error::SlotIsNotEmpty(slot) => {
                wlnfl!(f, "err-slot-is-not-empty", slot = slot_to_ui(slot))?
            }
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
                        wlnfl!(f, "rec-yk-no-service-win", url = url)?;
                    } else if cfg!(target_os = "macos") {
                        wlnfl!(f, "err-yk-no-service-macos")?;
                        let url = "https://apple.stackexchange.com/a/438198";
                        wlnfl!(f, "rec-yk-no-service-macos", url = url)?;
                    } else if cfg!(target_os = "openbsd") {
                        wlnfl!(f, "err-yk-no-service-pcscd")?;
                        let pkg = "pkg_add pcsc-lite ccid";
                        let service_enable = "rcctl enable pcscd";
                        let service_start = "rcctl start pcscd";
                        wlnfl!(
                            f,
                            "rec-yk-no-service-pcscd-bsd",
                            pkg = pkg,
                            service_enable = service_enable,
                            service_start = service_start
                        )?;
                    } else if cfg!(target_os = "freebsd") {
                        wlnfl!(f, "err-yk-no-service-pcscd")?;
                        let pkg = "pkg install pcsc-lite libccid";
                        let service_enable = "service pcscd enable";
                        let service_start = "service pcscd start";
                        wlnfl!(
                            f,
                            "rec-yk-no-service-pcscd-bsd",
                            pkg = pkg,
                            service_enable = service_enable,
                            service_start = service_start
                        )?;
                    } else {
                        wlnfl!(f, "err-yk-no-service-pcscd")?;
                        let apt = "sudo apt-get install pcscd";
                        wlnfl!(f, "rec-yk-no-service-pcscd", apt = apt)?;
                    }
                }
                yubikey::Error::WrongPin { tries } => wlnfl!(f, "err-yk-wrong-pin", tries = tries)?,
                e => {
                    wlnfl!(f, "err-yk-general", err = e.to_string())?;
                    use std::error::Error;
                    if let Some(inner) = e.source() {
                        wlnfl!(f, "err-yk-general-cause", inner_err = inner.to_string())?;
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
