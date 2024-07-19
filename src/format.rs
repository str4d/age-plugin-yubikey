use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, hkdf},
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::OsRng;
use sha2::Sha256;
use yubikey::piv::AlgorithmId;

use crate::key::YubikeyRecipient;

const TAG_BYTES: usize = 4;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) enum PublicKey {
    EccP256(p256::EncodedPoint),
    X25519(x25519_dalek::PublicKey),
}

impl PublicKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(pk) => pk.as_bytes(),
            Self::EccP256(pk) => pk.as_bytes(),
        }
    }

    pub(crate) fn decompress(&self) -> Option<p256::EncodedPoint> {
        match self {
            Self::EccP256(pk) => {
                let p = p256::PublicKey::from_encoded_point(pk).unwrap();
                Some(p.to_encoded_point(false))
            }
            _ => None,
        }
    }
}

/// The ephemeral key bytes in a piv-p256 stanza.
///
/// The bytes contain a compressed SEC-1 encoding of a valid point.
#[derive(Debug)]
pub(crate) struct EphemeralKeyBytes(PublicKey);

impl EphemeralKeyBytes {
    fn from_bytes(tag: &str, bytes: &[u8]) -> Option<Self> {
        match tag {
            crate::x25519::STANZA_TAG => {
                let key_bytes: [u8; crate::x25519::EPK_BYTES] = bytes.try_into().unwrap();
                match x25519_dalek::PublicKey::try_from(key_bytes) {
                    Ok(pk) => Some(EphemeralKeyBytes::from_public_key(PublicKey::X25519(pk))),
                    _ => None,
                }
            }
            _ => {
                let key_bytes: [u8; crate::p256::EPK_BYTES] = bytes.try_into().unwrap();
                let encoded = ::p256::EncodedPoint::from_bytes(key_bytes).ok()?;
                if encoded.is_compressed()
                    && p256::PublicKey::from_encoded_point(&encoded)
                        .is_some()
                        .into()
                {
                    Some(EphemeralKeyBytes::from_public_key(PublicKey::EccP256(
                        encoded,
                    )))
                } else {
                    None
                }
            }
        }
    }

    pub(crate) fn from_public_key(pk: PublicKey) -> Self {
        Self(pk)
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0.as_bytes()
    }

    pub(crate) fn algorithm(&self) -> AlgorithmId {
        match self.0 {
            PublicKey::EccP256(_) => AlgorithmId::EccP256,
            PublicKey::X25519(_) => AlgorithmId::X25519,
        }
    }

    pub(crate) fn tag(&self) -> String {
        match self.0 {
            PublicKey::EccP256(_) => crate::p256::STANZA_TAG.to_owned(),
            PublicKey::X25519(_) => crate::x25519::STANZA_TAG.to_owned(),
        }
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
            tag: r.epk_bytes.tag(),
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
        let algorithm = match s.tag.as_str() {
            crate::p256::STANZA_TAG => Some(AlgorithmId::EccP256),
            crate::x25519::STANZA_TAG => Some(AlgorithmId::X25519),
            _ => None,
        };
        if algorithm.is_none() {
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

        match algorithm {
            Some(AlgorithmId::X25519) => {
                let (tag, epk_bytes) = match &s.args[..] {
                    [tag, epk_bytes] => {
                        let base64_bytes =
                            base64_arg(epk_bytes, [0; crate::x25519::EPK_BYTES]).unwrap();
                        (
                            base64_arg(tag, [0; TAG_BYTES]),
                            EphemeralKeyBytes::from_bytes(&s.tag, &base64_bytes),
                        )
                    }
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
            _ => {
                let (tag, epk_bytes) = match &s.args[..] {
                    [tag, epk_bytes] => {
                        let base64_bytes =
                            base64_arg(epk_bytes, [0; crate::p256::EPK_BYTES]).unwrap();
                        (
                            base64_arg(tag, [0; TAG_BYTES]),
                            EphemeralKeyBytes::from_bytes(&s.tag, &base64_bytes),
                        )
                    }
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
    }

    pub(crate) fn wrap_file_key(file_key: &FileKey, recipient: &YubikeyRecipient) -> Self {
        match recipient {
            YubikeyRecipient::EccP256(pk) => {
                let esk =
                    ::p256::ecdh::EphemeralSecret::try_from_rng(&mut OsRng).expect("random key");
                let epk = esk.public_key().to_encoded_point(true);
                let epk_bytes = EphemeralKeyBytes::from_public_key(PublicKey::EccP256(epk.into()));

                let shared_secret = esk.diffie_hellman(pk.public_key());

                let mut salt = vec![];
                salt.extend_from_slice(epk_bytes.as_bytes());
                salt.extend_from_slice(pk.to_encoded().as_bytes());

                let enc_key = {
                    let mut okm = [0; 32];
                    shared_secret
                        .extract::<Sha256>(Some(&salt))
                        .expand(crate::p256::STANZA_KEY_LABEL, &mut okm)
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
            YubikeyRecipient::X25519(pk) => {
                let esk = x25519_dalek::EphemeralSecret::random();
                let epk = x25519_dalek::PublicKey::from(&esk);
                let epk_bytes = EphemeralKeyBytes::from_public_key(PublicKey::X25519(epk));

                let shared_secret = esk.diffie_hellman(pk.public_key());

                let mut salt = vec![];
                salt.extend_from_slice(epk_bytes.as_bytes());
                salt.extend_from_slice(pk.as_bytes());

                let enc_key = hkdf(
                    &salt,
                    crate::x25519::STANZA_KEY_LABEL,
                    shared_secret.as_bytes(),
                );

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
    }
}
