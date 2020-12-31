use std::fmt;
use std::io;

pub enum Error {
    Io(io::Error),
    MultipleCommands,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
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
