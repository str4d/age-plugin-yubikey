use std::fmt;
use std::marker::PhantomData;

use age_core::{
    format::{FileKey, Stanza},
    primitives::{bech32_encode_to_fmt, hpke_open, hpke_seal},
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use hpke::{Deserializable, Serializable};
use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint,
};
use rand::rngs::OsRng;
use yubikey::{certificate::PublicKeyInfo, Certificate};

use super::{stanza_tag, YubiKeyKemPrivateKey};
use crate::{
    key::{self, Connection},
    recipient::static_tag,
    util::base64_arg,
};

pub(crate) const PLUGIN_NAME: &str = "tag";
const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tag");

const P256TAG_RECIPIENT_TAG: &str = "p256tag";
const P256TAG_SALT: &str = "age-encryption.org/p256tag";

const TAG_BYTES: usize = 4;
/// Per [RFC 9180 section 7.1.1]:
/// > For P-256, P-384, and P-521, the `SerializePublicKey()` function of the KEM performs
/// > the uncompressed Elliptic-Curve-Point-to-Octet-String conversion according to [SECG].
///
/// [RFC 9180 section 7.1.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1
/// [SECG]: https://secg.org/sec1-v2.pdf
const ENC_BYTES: usize = 65;

type Kem = hpke::kem::DhP256HkdfSha256;

/// The non-hybrid tagged age recipient type, designed for hardware keys where decryption
/// potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Recipient {
    /// Compressed encoding of the recipient public key.
    compressed: EncodedPoint,
    /// Cached in-memory representation, for HPKE.
    pk_recip: <Kem as hpke::Kem>::PublicKey,
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, self.compressed.as_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Recipient {
    /// Attempts to parse a valid p256tag recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded = p256::EncodedPoint::from_bytes(bytes).ok()?;
        if !encoded.is_compressed() {
            return None;
        }

        let point = p256::PublicKey::from_encoded_point(&encoded).into_option()?;

        let pk_recip =
            <Kem as hpke::Kem>::PublicKey::from_bytes(point.to_encoded_point(false).as_bytes())
                .expect("valid");

        Some(Self {
            compressed: encoded,
            pk_recip,
        })
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: &PublicKeyInfo) -> Option<Self> {
        let encoded = match spki {
            PublicKeyInfo::EcP256(pubkey) => Some(pubkey),
            _ => None,
        }?;

        // Check that the certificate encoding is uncompressed.
        let pk_recip = <Kem as hpke::Kem>::PublicKey::from_bytes(encoded.as_bytes()).ok()?;

        let point = p256::PublicKey::from_encoded_point(encoded).into_option()?;
        let compressed = point.to_encoded_point(true);

        Some(Self {
            compressed,
            pk_recip,
        })
    }

    /// Returns the compressed SEC-1 encoding of this recipient.
    pub(crate) fn to_compressed(&self) -> p256::EncodedPoint {
        self.compressed
    }

    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.compressed.as_bytes())
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let (enc, ct) = hpke_seal::<Kem, _>(
            &self.pk_recip,
            P256TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut OsRng,
        );

        RecipientLine {
            tag: tag(&enc, self.static_tag()),
            enc,
            ct,
        }
    }
}

fn tag(enc: &<Kem as hpke::Kem>::EncappedKey, static_tag: [u8; TAG_BYTES]) -> [u8; TAG_BYTES] {
    let ikm = enc
        .to_bytes()
        .into_iter()
        .chain(static_tag)
        .collect::<Vec<u8>>();

    stanza_tag(&ikm, P256TAG_SALT)
}

pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    enc: <Kem as hpke::Kem>::EncappedKey,
    ct: Vec<u8>,
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: P256TAG_RECIPIENT_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(r.tag),
                BASE64_STANDARD_NO_PAD.encode(r.enc.to_bytes()),
            ],
            body: r.ct,
        }
    }
}

impl RecipientLine {
    pub(crate) fn from_stanza(s: &Stanza) -> Option<Result<Self, ()>> {
        if s.tag != P256TAG_RECIPIENT_TAG {
            return None;
        }

        let (tag, enc) = match &s.args[..] {
            [encoded_tag, encoded_enc] => (
                base64_arg(encoded_tag, [0; TAG_BYTES]),
                base64_arg(encoded_enc, [0; ENC_BYTES])
                    .and_then(|bytes| <Kem as hpke::Kem>::EncappedKey::from_bytes(&bytes[..]).ok()),
            ),
            _ => (None, None),
        };

        Some(match (tag, enc) {
            (Some(tag), Some(epk_bytes)) => Ok(RecipientLine {
                tag,
                enc: epk_bytes,
                ct: s.body.clone(),
            }),
            // Anything else indicates a structurally-invalid stanza.
            _ => Err(()),
        })
    }

    pub(crate) fn matches_stub(&self, stub: &key::Stub) -> bool {
        self.tag == tag(&self.enc, stub.tag)
    }

    pub(crate) fn unwrap_file_key(&self, conn: &mut Connection) -> Result<FileKey, ()> {
        // > The identity implementation [...] MUST check that the body length is exactly
        // > 32 bytes before attempting to decrypt it, to mitigate partitioning oracle
        // > attacks.
        if self.ct.len() != 32 {
            return Err(());
        }

        let sk_recip = YubiKeyKemPrivateKey::new(conn);

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        hpke_open::<YubiKeyDhP256HkdfSha256>(
            &self.enc,
            &sk_recip,
            P256TAG_SALT.as_bytes(),
            &self.ct,
        )
        .map_err(|_| ())
        .map(|mut pt| {
            FileKey::init_with_mut(|file_key| {
                file_key.copy_from_slice(&pt);
                pt.zeroize();
            })
        })
    }
}

/// A decap-only version of [`Kem`] where the private key is stored on a YubiKey.
struct YubiKeyDhP256HkdfSha256<'a>(PhantomData<&'a ()>);

impl<'a> hpke::Kem for YubiKeyDhP256HkdfSha256<'a> {
    type PublicKey = <Kem as hpke::Kem>::PublicKey;
    type PrivateKey = YubiKeyKemPrivateKey<'a, Kem>;

    fn sk_to_pk(_: &Self::PrivateKey) -> Self::PublicKey {
        unreachable!("Never called")
    }

    type EncappedKey = <Kem as hpke::Kem>::EncappedKey;
    type NSecret = <Kem as hpke::Kem>::NSecret;
    const KEM_ID: u16 = <Kem as hpke::Kem>::KEM_ID;

    fn derive_keypair(_: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        unreachable!("Never called")
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        let mut sk_recip = sk_recip.conn.write().unwrap();

        // Put together the binding context used for all KDF operations
        let suite_id = b"KEM\x00\x10";

        // Compute the shared secret from the ephemeral inputs
        let kex_res_eph = sk_recip
            .p256_ecdh(&encapped_key.to_bytes())
            .map_err(|_| hpke::HpkeError::DecapError)?;

        // Compute the sender's pubkey from their privkey
        let pk_recip = match sk_recip.recipient() {
            crate::recipient::Recipient::P256Tag(recipient) => &recipient.pk_recip,
            _ => panic!("should have been filtered out earlier"),
        };

        assert!(pk_sender_id.is_none());

        // kem_context = encapped_key || pk_recip || pk_sender_id
        let kem_context = [encapped_key.to_bytes(), pk_recip.to_bytes()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // The "unauthed shared secret" is derived from just the KEX of the ephemeral
        // input with the recipient pubkey. The HKDF-Expand call only errors if the
        // output values are 255x the digest size of the hash function. Since these
        // values are fixed at compile time, we don't worry about it.
        let mut shared_secret = <hpke::kem::SharedSecret<Self> as Default>::default();
        hpke::kdf::extract_and_expand::<hpke::kdf::HkdfSha256>(
            &kex_res_eph,
            suite_id,
            &kem_context,
            &mut shared_secret.0,
        )
        .expect("shared secret is way too big");
        Ok(shared_secret)
    }

    fn encap<R: rand::CryptoRng + rand::RngCore>(
        _: &Self::PublicKey,
        _: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        unreachable!("Never called")
    }
}
