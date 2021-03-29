//! Structs for handling YubiKeys.

use bech32::{ToBase32, Variant};
use dialoguer::Password;
use std::fmt;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use yubikey_piv::{key::RetiredSlotId, yubikey::Serial, MgmKey, Readers, YubiKey};

use crate::{
    error::Error,
    p256::{Recipient, TAG_BYTES},
    IDENTITY_PREFIX,
};

const ONE_SECOND: Duration = Duration::from_secs(1);
const FIFTEEN_SECONDS: Duration = Duration::from_secs(15);

pub(crate) fn wait_for_readers() -> Result<Readers, Error> {
    // Start a 15-second timer waiting for a YubiKey to be inserted (if necessary).
    let start = SystemTime::now();
    loop {
        let mut readers = Readers::open()?;
        if readers.iter()?.len() > 0 {
            break Ok(readers);
        }

        match SystemTime::now().duration_since(start) {
            Ok(end) if end >= FIFTEEN_SECONDS => return Err(Error::TimedOut),
            _ => sleep(ONE_SECOND),
        }
    }
}

pub(crate) fn open(serial: Option<Serial>) -> Result<YubiKey, Error> {
    if Readers::open()?.iter()?.len() == 0 {
        if let Some(serial) = serial {
            eprintln!("⏳ Please insert the YubiKey with serial {}.", serial);
        } else {
            eprintln!("⏳ Please insert the YubiKey.");
        }
    }
    let mut readers = wait_for_readers()?;
    let mut readers_iter = readers.iter()?;

    // --serial selects the YubiKey to use. If not provided, and more than one YubiKey is
    // connected, an error is returned.
    let yubikey = match (readers_iter.len(), serial) {
        (0, _) => unreachable!(),
        (1, None) => readers_iter.next().unwrap().open()?,
        (1, Some(serial)) => {
            let yubikey = readers_iter.next().unwrap().open()?;
            if yubikey.serial() != serial {
                return Err(Error::NoMatchingSerial(serial));
            }
            yubikey
        }
        (_, Some(serial)) => {
            let reader = readers_iter
                .find(|reader| match reader.open() {
                    Ok(yk) => yk.serial() == serial,
                    _ => false,
                })
                .ok_or(Error::NoMatchingSerial(serial))?;
            reader.open()?
        }
        (_, None) => return Err(Error::MultipleYubiKeys),
    };

    Ok(yubikey)
}

pub(crate) fn manage(yubikey: &mut YubiKey) -> Result<(), Error> {
    eprintln!("");
    let pin = Password::new()
        .with_prompt(&format!(
            "Enter PIN for YubiKey with serial {} (default is 123456)",
            yubikey.serial(),
        ))
        .interact()?;
    yubikey.verify_pin(pin.as_bytes())?;

    // If the user is using the default PIN, help them to change it.
    if pin == "123456" {
        eprintln!("");
        eprintln!("✨ Your key is using the default PIN. Let's change it!");
        eprintln!("✨ We'll also set the PUK equal to the PIN.");
        eprintln!("");
        eprintln!("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!");
        eprintln!(
            "❌ Your keys will be lost if the PIN and PUK are locked after 3 incorrect tries."
        );
        eprintln!("");
        let current_puk = Password::new()
            .with_prompt("Enter current PUK (default is 12345678)")
            .interact()?;
        let new_pin = Password::new()
            .with_prompt("Choose a new PIN/PUK")
            .with_confirmation("Repeat the PIN/PUK", "PINs don't match")
            .interact()?;
        if new_pin.len() > 8 {
            return Err(Error::InvalidPinLength);
        }
        yubikey.change_puk(current_puk.as_bytes(), new_pin.as_bytes())?;
        yubikey.change_pin(pin.as_bytes(), new_pin.as_bytes())?;
    }

    if let Ok(mgm_key) = MgmKey::get_protected(yubikey) {
        yubikey.authenticate(mgm_key)?;
    } else {
        // Try to authenticate with the default management key.
        yubikey
            .authenticate(MgmKey::default())
            .map_err(|_| Error::CustomManagementKey)?;

        // Migrate to a PIN-protected management key.
        let mgm_key = MgmKey::generate()?;
        mgm_key.set_protected(yubikey)?;
    }

    Ok(())
}

/// A reference to an age key stored in a YubiKey.
#[derive(Debug)]
pub struct Stub {
    pub(crate) serial: Serial,
    pub(crate) slot: RetiredSlotId,
    pub(crate) tag: [u8; TAG_BYTES],
    identity_index: usize,
}

impl fmt::Display for Stub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(
                IDENTITY_PREFIX,
                self.to_bytes().to_base32(),
                Variant::Bech32,
            )
            .expect("HRP is valid")
            .to_uppercase()
            .as_str(),
        )
    }
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub(crate) fn new(serial: Serial, slot: RetiredSlotId, recipient: &Recipient) -> Self {
        Stub {
            serial,
            slot,
            tag: recipient.tag(),
            identity_index: 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }
}
