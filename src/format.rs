use age_core::{
    format::{FileKey, Stanza},
    primitives::aead_encrypt,
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::{p256::Recipient, STANZA_TAG};

pub(crate) const STANZA_KEY_LABEL: &[u8] = b"piv-p256";

const TAG_BYTES: usize = 4;
const EPK_BYTES: usize = 33;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

/// The ephemeral key bytes in a piv-p256 stanza.
///
/// The bytes contain a compressed SEC-1 encoding of a valid point.
#[derive(Debug)]
pub(crate) struct EphemeralKeyBytes(p256::EncodedPoint);

impl EphemeralKeyBytes {
    fn from_bytes(bytes: [u8; EPK_BYTES]) -> Option<Self> {
        let encoded = p256::EncodedPoint::from_bytes(&bytes).ok()?;
        if encoded.is_compressed()
            && p256::PublicKey::from_encoded_point(&encoded)
                .is_some()
                .into()
        {
            Some(EphemeralKeyBytes(encoded))
        } else {
            None
        }
    }

    fn from_public_key(epk: &p256::PublicKey) -> Self {
        EphemeralKeyBytes(epk.to_encoded_point(true))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn decompress(&self) -> p256::EncodedPoint {
        // EphemeralKeyBytes is a valid compressed encoding by construction.
        let p = p256::PublicKey::from_encoded_point(&self.0).unwrap();
        p.to_encoded_point(false)
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
                BASE64_STANDARD_NO_PAD.encode(&r.tag),
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

        fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
            if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
                return None;
            }

            BASE64_STANDARD_NO_PAD
                .decode_slice_unchecked(arg, buf.as_mut())
                .ok()
                .and_then(|len| (len == buf.as_mut().len()).then_some(buf))
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

    pub(crate) fn wrap_file_key(file_key: &FileKey, pk: &Recipient) -> Self {
        let esk = EphemeralSecret::random(&mut OsRng);
        let epk = esk.public_key();
        let epk_bytes = EphemeralKeyBytes::from_public_key(&epk);

        let shared_secret = esk.diffie_hellman(pk.public_key());

        let mut salt = vec![];
        salt.extend_from_slice(epk_bytes.as_bytes());
        salt.extend_from_slice(pk.to_encoded().as_bytes());

        let enc_key = {
            let mut okm = [0; 32];
            shared_secret
                .extract::<Sha256>(Some(&salt))
                .expand(STANZA_KEY_LABEL, &mut okm)
                .expect("okm is the correct length");
            okm
        };

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientLine {
            tag: pk.tag(),
            epk_bytes,
            encrypted_file_key,
        }
    }
}
