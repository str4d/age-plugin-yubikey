use std::fmt;
use std::io;

pub enum Error {
    Io(io::Error),
    MultipleCommands,
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
            Error::Io(e) => writeln!(f, "Failed to set up YubiKey: {}", e)?,
            Error::MultipleCommands => writeln!(
                f,
                "Only one of --generate, --identity, --list, --list-all can be specified."
            )?,
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
