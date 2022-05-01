//! Structs for handling YubiKeys.

use age_core::{
    format::{FileKey, FILE_KEY_BYTES},
    primitives::{aead_decrypt, hkdf},
    secrecy::ExposeSecret,
};
use age_plugin::{identity, Callbacks};
use bech32::{ToBase32, Variant};
use dialoguer::Password;
use log::warn;
use std::fmt;
use std::io;
use std::iter;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};
use yubikey::{
    certificate::{Certificate, PublicKeyInfo},
    piv::{decrypt_data, AlgorithmId, RetiredSlotId, SlotId},
    reader::{Context, Reader},
    MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    format::{RecipientLine, STANZA_KEY_LABEL},
    p256::{Recipient, TAG_BYTES},
    util::{otp_serial_prefix, Metadata},
    IDENTITY_PREFIX,
};

const ONE_SECOND: Duration = Duration::from_secs(1);
const FIFTEEN_SECONDS: Duration = Duration::from_secs(15);

pub(crate) fn is_connected(reader: Reader) -> bool {
    filter_connected(&reader)
}

pub(crate) fn filter_connected(reader: &Reader) -> bool {
    match reader.open() {
        Ok(_) => true,
        Err(e) => {
            use std::error::Error;
            if let Some(pcsc::Error::RemovedCard) =
                e.source().and_then(|inner| inner.downcast_ref())
            {
                warn!(
                    "{}",
                    i18n_embed_fl::fl!(
                        crate::LANGUAGE_LOADER,
                        "warn-yk-not-connected",
                        yubikey_name = reader.name(),
                    )
                );
                false
            } else {
                true
            }
        }
    }
}

pub(crate) fn wait_for_readers() -> Result<Context, Error> {
    // Start a 15-second timer waiting for a YubiKey to be inserted (if necessary).
    let start = SystemTime::now();
    loop {
        let mut readers = Context::open()?;
        if readers.iter()?.any(is_connected) {
            break Ok(readers);
        }

        match SystemTime::now().duration_since(start) {
            Ok(end) if end >= FIFTEEN_SECONDS => return Err(Error::TimedOut),
            _ => sleep(ONE_SECOND),
        }
    }
}

pub(crate) fn open(serial: Option<Serial>) -> Result<YubiKey, Error> {
    if !Context::open()?.iter()?.any(is_connected) {
        if let Some(serial) = serial {
            eprintln!(
                "{}",
                i18n_embed_fl::fl!(
                    crate::LANGUAGE_LOADER,
                    "open-yk-with-serial",
                    yubikey_serial = serial.to_string(),
                )
            );
        } else {
            eprintln!("{}", fl!("open-yk-without-serial"));
        }
    }
    let mut readers = wait_for_readers()?;
    let mut readers_iter = readers.iter()?.filter(filter_connected);

    // --serial selects the YubiKey to use. If not provided, and more than one YubiKey is
    // connected, an error is returned.
    let yubikey = match (readers_iter.next(), readers_iter.next(), serial) {
        (None, _, _) => unreachable!(),
        (Some(reader), None, None) => reader.open()?,
        (Some(reader), None, Some(serial)) => {
            let yubikey = reader.open()?;
            if yubikey.serial() != serial {
                return Err(Error::NoMatchingSerial(serial));
            }
            yubikey
        }
        (Some(a), Some(b), Some(serial)) => {
            let reader = iter::empty()
                .chain(Some(a))
                .chain(Some(b))
                .chain(readers_iter)
                .find(|reader| match reader.open() {
                    Ok(yk) => yk.serial() == serial,
                    _ => false,
                })
                .ok_or(Error::NoMatchingSerial(serial))?;
            reader.open()?
        }
        (Some(_), Some(_), None) => return Err(Error::MultipleYubiKeys),
    };

    Ok(yubikey)
}

pub(crate) fn manage(yubikey: &mut YubiKey) -> Result<(), Error> {
    const DEFAULT_PIN: &str = "123456";
    const DEFAULT_PUK: &str = "12345678";

    eprintln!();
    let pin = Password::new()
        .with_prompt(i18n_embed_fl::fl!(
            crate::LANGUAGE_LOADER,
            "mgr-enter-pin",
            yubikey_serial = yubikey.serial().to_string(),
            default_pin = DEFAULT_PIN,
        ))
        .interact()?;
    yubikey.verify_pin(pin.as_bytes())?;

    // If the user is using the default PIN, help them to change it.
    if pin == DEFAULT_PIN {
        eprintln!();
        eprintln!("{}", fl!("mgr-change-default-pin"));
        eprintln!();
        let current_puk = Password::new()
            .with_prompt(i18n_embed_fl::fl!(
                crate::LANGUAGE_LOADER,
                "mgr-enter-current-puk",
                default_puk = DEFAULT_PUK,
            ))
            .interact()?;
        let new_pin = Password::new()
            .with_prompt(fl!("mgr-choose-new-pin"))
            .with_confirmation(fl!("mgr-repeat-new-pin"), fl!("mgr-pin-mismatch"))
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
        let mgm_key = MgmKey::generate();
        eprintln!();
        eprintln!("{}", fl!("mgr-changing-mgmt-key"));
        eprint!("... ");
        mgm_key.set_protected(yubikey).map_err(|e| {
            eprintln!(
                "{}",
                i18n_embed_fl::fl!(
                    crate::LANGUAGE_LOADER,
                    "mgr-changing-mgmt-key-error",
                    management_key = hex::encode(mgm_key.as_ref()),
                )
            );
            e
        })?;
        eprintln!("{}", fl!("mgr-changing-mgmt-key-success"));
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

impl PartialEq for Stub {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
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

    pub(crate) fn from_bytes(bytes: &[u8], identity_index: usize) -> Option<Self> {
        let serial = Serial::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
        let slot: RetiredSlotId = bytes[4].try_into().ok()?;
        Some(Stub {
            serial,
            slot,
            tag: bytes[5..9].try_into().unwrap(),
            identity_index,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    pub(crate) fn matches(&self, line: &RecipientLine) -> bool {
        self.tag == line.tag
    }

    pub(crate) fn connect<E>(
        &self,
        callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<Connection, identity::Error>> {
        let mut yubikey = match YubiKey::open_by_serial(self.serial) {
            Ok(yk) => yk,
            Err(yubikey::Error::NotFound) => {
                if callbacks
                    .message(&i18n_embed_fl::fl!(
                        crate::LANGUAGE_LOADER,
                        "plugin-insert-yk",
                        yubikey_serial = self.serial.to_string(),
                    ))?
                    .is_err()
                {
                    return Ok(Err(identity::Error::Identity {
                        index: self.identity_index,
                        message: i18n_embed_fl::fl!(
                            crate::LANGUAGE_LOADER,
                            "plugin-err-yk-not-found",
                            yubikey_serial = self.serial.to_string(),
                        ),
                    }));
                }

                // Start a 15-second timer waiting for the YubiKey to be inserted
                let start = SystemTime::now();
                loop {
                    match YubiKey::open_by_serial(self.serial) {
                        Ok(yubikey) => break yubikey,
                        Err(yubikey::Error::NotFound) => (),
                        Err(_) => {
                            return Ok(Err(identity::Error::Identity {
                                index: self.identity_index,
                                message: i18n_embed_fl::fl!(
                                    crate::LANGUAGE_LOADER,
                                    "plugin-err-yk-opening",
                                    yubikey_serial = self.serial.to_string(),
                                ),
                            }));
                        }
                    }

                    match SystemTime::now().duration_since(start) {
                        Ok(end) if end >= FIFTEEN_SECONDS => {
                            return Ok(Err(identity::Error::Identity {
                                index: self.identity_index,
                                message: i18n_embed_fl::fl!(
                                    crate::LANGUAGE_LOADER,
                                    "plugin-err-yk-timed-out",
                                    yubikey_serial = self.serial.to_string(),
                                ),
                            }))
                        }
                        _ => sleep(ONE_SECOND),
                    }
                }
            }
            Err(_) => {
                return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message: i18n_embed_fl::fl!(
                        crate::LANGUAGE_LOADER,
                        "plugin-err-yk-opening",
                        yubikey_serial = self.serial.to_string(),
                    ),
                }))
            }
        };

        // Read the pubkey from the YubiKey slot and check it still matches.
        let (cert, pk) = match Certificate::read(&mut yubikey, SlotId::Retired(self.slot))
            .ok()
            .and_then(|cert| match cert.subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => Recipient::from_encoded(pubkey)
                    .filter(|pk| pk.tag() == self.tag)
                    .map(|pk| (cert, pk)),
                _ => None,
            }) {
            Some(pk) => pk,
            None => {
                return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message: fl!("plugin-err-yk-stub-mismatch"),
                }))
            }
        };

        Ok(Ok(Connection {
            yubikey,
            cert,
            pk,
            slot: self.slot,
            tag: self.tag,
            identity_index: self.identity_index,
            cached_metadata: None,
            last_touch: None,
        }))
    }
}

pub(crate) struct Connection {
    yubikey: YubiKey,
    cert: Certificate,
    pk: Recipient,
    slot: RetiredSlotId,
    tag: [u8; 4],
    identity_index: usize,
    cached_metadata: Option<Metadata>,
    last_touch: Option<Instant>,
}

impl Connection {
    pub(crate) fn recipient(&self) -> &Recipient {
        &self.pk
    }

    pub(crate) fn request_pin_if_necessary<E>(
        &mut self,
        callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<(), identity::Error>> {
        // Check if we can skip requesting a PIN.
        if self.cached_metadata.is_none() {
            let (_, cert) = x509_parser::parse_x509_certificate(self.cert.as_ref()).unwrap();
            self.cached_metadata =
                match Metadata::extract(&mut self.yubikey, self.slot, &cert, true) {
                    None => {
                        return Ok(Err(identity::Error::Identity {
                            index: self.identity_index,
                            message: fl!("plugin-err-yk-invalid-pin-policy"),
                        }))
                    }
                    metadata => metadata,
                };
        }
        if let Some(PinPolicy::Never) = self.cached_metadata.as_ref().and_then(|m| m.pin_policy) {
            return Ok(Ok(()));
        }

        // The policy requires a PIN, so request it.
        // Note that we can't distinguish between PinPolicy::Once and PinPolicy::Always
        // because this plugin is ephemeral, so we always request the PIN.
        let enter_pin_msg = i18n_embed_fl::fl!(
            crate::LANGUAGE_LOADER,
            "plugin-enter-pin",
            yubikey_serial = self.yubikey.serial().to_string(),
        );
        let mut message = enter_pin_msg.clone();
        let pin = loop {
            message = match callbacks.request_secret(&message)? {
                Ok(pin) => match pin.expose_secret().len() {
                    // A PIN must be between 6 and 8 characters.
                    6..=8 => break pin,
                    // If the string is 44 bytes and starts with the YubiKey's serial
                    // encoded as 12-byte modhex, the user probably touched the YubiKey
                    // early and "typed" an OTP.
                    44 if pin
                        .expose_secret()
                        .starts_with(&otp_serial_prefix(self.yubikey.serial())) =>
                    {
                        format!("{} {}", fl!("plugin-err-accidental-touch"), enter_pin_msg)
                    }
                    // Otherwise, the PIN is either too short or too long.
                    0..=5 => format!("{} {}", fl!("plugin-err-pin-too-short"), enter_pin_msg),
                    _ => format!("{} {}", fl!("plugin-err-pin-too-long"), enter_pin_msg),
                },
                Err(_) => {
                    return Ok(Err(identity::Error::Identity {
                        index: self.identity_index,
                        message: i18n_embed_fl::fl!(
                            crate::LANGUAGE_LOADER,
                            "plugin-err-pin-required",
                            yubikey_serial = self.yubikey.serial().to_string(),
                        ),
                    }))
                }
            };
        };
        if let Err(e) = self.yubikey.verify_pin(pin.expose_secret().as_bytes()) {
            return Ok(Err(identity::Error::Identity {
                index: self.identity_index,
                message: format!("{:?}", Error::YubiKey(e)),
            }));
        }
        Ok(Ok(()))
    }

    pub(crate) fn unwrap_file_key<E>(
        &mut self,
        line: &RecipientLine,
        callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<FileKey, ()>> {
        assert_eq!(self.tag, line.tag);

        // If the touch policy requires it, request a touch.
        let requested_touch = match (
            self.cached_metadata.as_ref().and_then(|m| m.touch_policy),
            self.last_touch,
        ) {
            (Some(TouchPolicy::Always), _) | (Some(TouchPolicy::Cached), None) => {
                callbacks.message(&fl!("plugin-touch-yk"))?.unwrap();
                true
            }
            (Some(TouchPolicy::Cached), Some(last)) if last.elapsed() >= FIFTEEN_SECONDS => {
                callbacks.message(&fl!("plugin-touch-yk"))?.unwrap();
                true
            }
            _ => false,
        };

        // The YubiKey API for performing scalar multiplication takes the point in its
        // uncompressed SEC-1 encoding.
        let shared_secret = match decrypt_data(
            &mut self.yubikey,
            line.epk_bytes.decompress().as_bytes(),
            AlgorithmId::EccP256,
            SlotId::Retired(self.slot),
        ) {
            Ok(res) => res,
            Err(_) => return Ok(Err(())),
        };

        // If we requested a touch and reached here, the user touched the YubiKey.
        if requested_touch {
            if let Some(TouchPolicy::Cached) =
                self.cached_metadata.as_ref().and_then(|m| m.touch_policy)
            {
                self.last_touch = Some(Instant::now());
            }
        }

        let mut salt = vec![];
        salt.extend_from_slice(line.epk_bytes.as_bytes());
        salt.extend_from_slice(self.pk.to_encoded().as_bytes());

        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared_secret.as_ref());

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        match aead_decrypt(&enc_key, FILE_KEY_BYTES, &line.encrypted_file_key) {
            Ok(pt) => Ok(Ok(TryInto::<[u8; FILE_KEY_BYTES]>::try_into(&pt[..])
                .unwrap()
                .into())),
            Err(_) => Ok(Err(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use yubikey::{piv::RetiredSlotId, Serial};

    use super::Stub;

    #[test]
    fn stub_round_trip() {
        let stub = Stub {
            serial: Serial::from(42),
            slot: RetiredSlotId::R1,
            tag: [7; 4],
            identity_index: 0,
        };

        let encoded = stub.to_bytes();
        assert_eq!(Stub::from_bytes(&encoded, 0), Some(stub));
    }
}
