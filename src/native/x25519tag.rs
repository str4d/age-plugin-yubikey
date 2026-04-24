use std::fmt;
use std::marker::PhantomData;

use age_core::{
    format::{FileKey, Stanza},
    primitives::bech32_encode_to_fmt,
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use hpke::{Deserializable, Serializable};
use x509_cert::spki::{ObjectIdentifier, SubjectPublicKeyInfoRef};
use yubikey::Certificate;

use super::{stanza_tag, YubiKeyKemPrivateKey};
use crate::{
    key::{self, Connection},
    recipient::static_tag,
    util::base64_arg,
};

pub const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tag");

pub(crate) const X25519TAG_RECIPIENT_TAG: &str = "x25519tag";
const X25519TAG_SALT: &str = "age-encryption.org/x25519tag";

const TAG_BYTES: usize = 4;
/// Per [RFC 9180 section 7.1.1]:
/// > For P-256, P-384, and P-521, the `SerializePublicKey()` function of the KEM performs
/// > the uncompressed Elliptic-Curve-Point-to-Octet-String conversion according to [SECG].
///
/// [RFC 9180 section 7.1.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1
/// [SECG]: https://secg.org/sec1-v2.pdf
const ENC_BYTES: usize = 32;

/// TODO: Remove these rewrites when age-core update rand lib
fn hpke_seal<R: hpke::rand_core::CryptoRng + hpke::rand_core::Rng>(
    pk_recip: &<Kem as hpke::Kem>::PublicKey,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> (<Kem as hpke::Kem>::EncappedKey, Vec<u8>) {
    hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem, R>(
        &hpke::OpModeS::Base,
        pk_recip,
        info,
        plaintext,
        &[],
        rng,
    )
    .expect("no errors should occur with these HPKE parameters")
}

pub fn hpke_open<Kem: hpke::Kem>(
    encapped_key: &<Kem as hpke::Kem>::EncappedKey,
    sk_recip: &Kem::PrivateKey,
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, hpke::HpkeError> {
    hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem>(
        &hpke::OpModeR::Base,
        sk_recip,
        encapped_key,
        info,
        ciphertext,
        &[],
    )
}

type Kem = hpke::kem::X25519HkdfSha256;

/// The non-hybrid tagged age recipient type, designed for hardware keys where decryption
/// potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Recipient {
    pk: x25519_dalek::PublicKey,
    pk_recip: <Kem as hpke::Kem>::PublicKey,
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, &self.pk.to_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Recipient {
    /// Attempts to parse a valid x25519tag recipient.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let pk_bytes: [u8; 32] = bytes.try_into().expect("pubkey length");
        let pk = x25519_dalek::PublicKey::from(pk_bytes);
        let pk_recip = <Kem as hpke::Kem>::PublicKey::from_bytes(&pk_bytes).expect("valid");

        Some(Self { pk, pk_recip })
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.pk.to_bytes()
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        let pk_bytes: [u8; 32] = spki
            .subject_public_key
            .raw_bytes()
            .try_into()
            .expect("spki length");
        Self::from_bytes(&pk_bytes)
    }

    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        static_tag(&self.pk.to_bytes())
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let mut csprng = rand::rng();
        let (enc, ct) = hpke_seal(
            &self.pk_recip,
            X25519TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut csprng,
        );

        RecipientLine {
            tag: tag(&enc, self.static_tag()),
            enc,
            ct,
        }
    }

    pub(crate) fn public_key(&self) -> &x25519_dalek::PublicKey {
        &self.pk
    }
}

fn tag(enc: &<Kem as hpke::Kem>::EncappedKey, static_tag: [u8; TAG_BYTES]) -> [u8; TAG_BYTES] {
    let ikm = enc
        .to_bytes()
        .into_iter()
        .chain(static_tag)
        .collect::<Vec<u8>>();

    stanza_tag(&ikm, X25519TAG_SALT)
}

pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    enc: <Kem as hpke::Kem>::EncappedKey,
    ct: Vec<u8>,
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: X25519TAG_RECIPIENT_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(r.tag),
                BASE64_STANDARD_NO_PAD.encode(r.enc.to_bytes()),
            ],
            body: r.ct,
        }
    }
}

impl RecipientLine {
    pub(crate) fn from_stanza(s: Stanza) -> Option<Result<Self, ()>> {
        if s.tag != X25519TAG_RECIPIENT_TAG {
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
                ct: s.body,
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
        hpke_open::<YubiKeyX25519HkdfSha256>(
            &self.enc,
            &sk_recip,
            X25519TAG_SALT.as_bytes(),
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
struct YubiKeyX25519HkdfSha256<'a>(PhantomData<&'a ()>);

impl<'a> hpke::Kem for YubiKeyX25519HkdfSha256<'a> {
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
        let suite_id = b"KEM\x00\x20";

        // Compute the shared secret from the ephemeral inputs
        let kex_res_eph = sk_recip
            .ecdh(&encapped_key.to_bytes())
            .map_err(|_| hpke::HpkeError::DecapError)?;

        // Compute the sender's pubkey from their privkey
        let pk_recip = match sk_recip.recipient() {
            crate::recipient::Recipient::X25519Tag(recipient) => &recipient.pk_recip,
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

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::Rng>(
        _: &Self::PublicKey,
        _: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        unreachable!("Never called")
    }
}
