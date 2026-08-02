use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt, hkdf},
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{key::Connection, util::base64_arg};

pub(crate) const TAG_BYTES: usize = 4;
pub(crate) const STANZA_TAG: &str = "piv-x25519";

const EPK_BYTES: usize = 32;
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"piv-x25519";
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

mod recipient;
pub(crate) use recipient::Recipient;

#[derive(Debug)]
pub(crate) struct EphemeralKeyBytes(x25519_dalek::PublicKey);

impl EphemeralKeyBytes {
    fn from_bytes(bytes: [u8; EPK_BYTES]) -> Option<Self> {
        let encoded = x25519_dalek::PublicKey::from(bytes);
        Some(EphemeralKeyBytes(encoded))
    }

    fn from_public_key(epk: &x25519_dalek::PublicKey) -> Self {
        EphemeralKeyBytes(*epk)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: [u8; TAG_BYTES],
    pub(crate) epk_bytes: EphemeralKeyBytes,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(r.tag),
                BASE64_STANDARD_NO_PAD.encode(r.epk_bytes.as_bytes()),
            ],
            body: r.encrypted_file_key.to_vec(),
        }
    }
}

impl RecipientLine {
    pub(super) fn from_stanza(s: &Stanza) -> Option<Result<Self, ()>> {
        if s.tag != STANZA_TAG {
            return None;
        }

        let (tag, epk_bytes) = match &s.args[..] {
            [tag, epk_bytes] => (
                base64_arg(tag, [0; TAG_BYTES]),
                base64_arg(epk_bytes, [0; EPK_BYTES]).and_then(EphemeralKeyBytes::from_bytes),
            ),
            _ => (None, None),
        };

        Some(match (tag, epk_bytes, s.body[..].try_into()) {
            (Some(tag), Some(epk_bytes), Ok(encrypted_file_key)) => Ok(RecipientLine {
                tag,
                epk_bytes,
                encrypted_file_key,
            }),
            // Anything else indicates a structurally-invalid stanza.
            _ => Err(()),
        })
    }
}

impl Recipient {
    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let mut csprng = rand::rng();
        let esk = EphemeralSecret::random_from_rng(&mut csprng);
        let epk = PublicKey::from(&esk);
        let epk_bytes = EphemeralKeyBytes::from_public_key(&epk);

        let shared_secret = esk.diffie_hellman(self.public_key());

        let salt = salt(&epk_bytes, *self.public_key());

        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared_secret.as_bytes());

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientLine {
            tag: self.tag(),
            epk_bytes,
            encrypted_file_key,
        }
    }
}

impl RecipientLine {
    pub(crate) fn unwrap_file_key(&self, conn: &mut Connection) -> Result<FileKey, ()> {
        let (static_tag, pk) = match conn.recipient() {
            crate::recipient::Recipient::PivX25519(recipient) => {
                (recipient.tag(), recipient.public_key())
            }
            crate::recipient::Recipient::X25519Tag(recipient) => {
                (recipient.static_tag(), recipient.public_key())
            }
            _ => panic!("Unsupported recipient"),
        };
        assert_eq!(self.tag, static_tag);

        let salt = salt(&self.epk_bytes, *pk);

        // The YubiKey API for performing scalar multiplication
        let shared_secret = conn.ecdh(self.epk_bytes.as_bytes())?;

        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared_secret.as_ref());

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        aead_decrypt(&enc_key, FILE_KEY_BYTES, &self.encrypted_file_key)
            .map_err(|_| ())
            .map(|mut pt| {
                FileKey::init_with_mut(|file_key| {
                    file_key.copy_from_slice(&pt);
                    pt.zeroize();
                })
            })
    }
}

fn salt(epk_bytes: &EphemeralKeyBytes, pk: PublicKey) -> Vec<u8> {
    let mut salt = vec![];
    salt.extend_from_slice(epk_bytes.as_bytes());
    salt.extend_from_slice(pk.as_bytes());
    salt
}
