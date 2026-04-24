use std::{fmt, marker::PhantomData};

use age_core::{
    format::{FileKey, Stanza},
    primitives::bech32_encode_to_fmt,
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use ml_kem::{kem::Decapsulate, ml_kem_768, Encapsulate, FromSeed, KeyExport, TryKeyInit};
use sha3::{
    digest::{Digest as Sha3Digest, ExtendableOutput, FixedOutput, Update, XofReader},
    Sha3_256, Shake256,
};
use typenum::{UInt, UTerm, Unsigned, B0, B1, U32};
use yubikey::Certificate;

use super::{stanza_tag, YubiKeyKemPrivateKey};
use crate::{
    key::{self, Connection},
    recipient::static_tag,
    util::base64_arg,
};

const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tagpq");

pub(crate) const MLKEM768X25519TAG_RECIPIENT_TAG: &str = "mlkem768x25519tag";
const MLKEM768X25519TAG_SALT: &str = "age-encryption.org/mlkem768x25519tag";
const LABEL: &str = "\\.//^\\";

const TAG_BYTES: usize = 4;
/// Per [RFC 9180 section 7.1.1]:
/// > For P-256, P-384, and P-521, the `SerializePublicKey()` function of the KEM performs
/// > the uncompressed Elliptic-Curve-Point-to-Octet-String conversion according to [SECG].
///
/// [RFC 9180 section 7.1.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1
/// [SECG]: https://secg.org/sec1-v2.pdf
const ENC_BYTES: usize = 1120;

/// TODO: Remove these rewrites when age-core update rand lib
fn hpke_seal<R: hpke::rand_core::CryptoRng + hpke::rand_core::Rng>(
    pk_recip: &<MlKem768X25519 as KemTrait>::PublicKey,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> (<MlKem768X25519 as KemTrait>::EncappedKey, Vec<u8>) {
    hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, MlKem768X25519, R>(
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

#[derive(Clone, Debug)]
pub struct PublicKey {
    ek: [u8; 1216],
    ek_pq: ml_kem_768::EncapsulationKey,
    ek_t: x25519_dalek::PublicKey,
}

impl PublicKey {
    pub fn from(ek_pq: ml_kem_768::EncapsulationKey, ek_t: x25519_dalek::PublicKey) -> Self {
        let mut ek_bytes = [0; 1216];
        ek_bytes[..1184].copy_from_slice(ek_pq.to_bytes().as_slice());
        ek_bytes[1184..].copy_from_slice(ek_t.to_bytes().as_slice());
        Self {
            ek: ek_bytes,
            ek_pq,
            ek_t,
        }
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ek == other.ek
    }
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        if encoded.len() != 1216 {
            return Err(hpke::HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        };
        let ek_pq =
            ml_kem_768::EncapsulationKey::new_from_slice(&encoded[..1184]).expect("ek_pq length");
        let mut ek_t_bytes = [0; 32];
        ek_t_bytes.copy_from_slice(&encoded[1184..]);
        let ek_t = x25519_dalek::PublicKey::try_from(ek_t_bytes).expect("ek_t length");
        Ok(PublicKey::from(ek_pq, ek_t))
    }
}

impl Serializable for PublicKey {
    type OutputSize = UInt<
        UInt<
            UInt<
                UInt<
                    UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B1>, B0>, B0>,
                    B0,
                >,
                B0,
            >,
            B0,
        >,
        B0,
    >;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.ek);
    }
}

pub struct ExpandedKey {
    pub(crate) ek_pq: ml_kem_768::EncapsulationKey,
    pub(crate) ek_t: x25519_dalek::PublicKey,
    pub(crate) dk_pq: ml_kem_768::DecapsulationKey,
    pub(crate) dk_t: x25519_dalek::StaticSecret,
}

impl ExpandedKey {
    fn from(seed: &[u8; 32]) -> Self {
        let mut seed_bytes_pq = [0; 64];
        let mut seed_bytes_t = [0; 32];
        let mut xof = sha3::Shake256::default().chain(seed).finalize_xof();
        xof.read(&mut seed_bytes_pq);
        xof.read(&mut seed_bytes_t);

        let seed_pq = ml_kem::Seed::try_from(seed_bytes_pq).unwrap();
        let (dk_pq, ek_pq) = ml_kem::MlKem768::from_seed(&seed_pq);

        let dk_t = x25519_dalek::StaticSecret::try_from(seed_bytes_t).expect("ek_t static secret");
        let ek_t = x25519_dalek::PublicKey::from(&dk_t);

        ExpandedKey {
            ek_pq,
            ek_t,
            dk_pq,
            dk_t,
        }
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    seed: [u8; 32],
    dk_pq: ml_kem_768::DecapsulationKey,
    dk_t: x25519_dalek::StaticSecret,
}

impl PrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.seed
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}

impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let seed: [u8; 32] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        let expanded_key = ExpandedKey::from(&seed);
        Ok(Self {
            seed,
            dk_pq: expanded_key.dk_pq,
            dk_t: expanded_key.dk_t,
        })
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.seed);
    }
}

#[derive(Clone, Debug)]
pub struct EncappedKey([u8; 1120]);

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let encapped_key: [u8; 1120] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(encapped_key))
    }
}

impl Serializable for EncappedKey {
    type OutputSize = UInt<
        UInt<
            UInt<
                UInt<
                    UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B1>, B0>,
                    B0,
                >,
                B0,
            >,
            B0,
        >,
        B0,
    >;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

pub struct MlKem768X25519;

impl KemTrait for MlKem768X25519 {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        let seed: [u8; 32] = sk.as_bytes().try_into().expect("correct length");
        let expanded_key = ExpandedKey::from(&seed);
        PublicKey::from(expanded_key.ek_pq, expanded_key.ek_t)
    }

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed = [0; 32];
        Shake256::default()
            .chain(&ikm)
            .chain(b"HPKE-v1")
            .chain(b"KEM")
            .chain(Self::KEM_ID.to_be_bytes())
            .chain(
                u16::try_from(b"DeriveKeyPair".len())
                    .expect("short enough")
                    .to_be_bytes(),
            )
            .chain(b"DeriveKeyPair")
            .chain(u16::try_from(32).expect("short enough").to_be_bytes())
            .chain(b"")
            .finalize_xof_into(&mut seed);

        let dk = PrivateKey::from_bytes(&seed).expect("private key");
        let ek = Self::sk_to_pk(&dk);
        (dk, ek)
    }

    fn gen_keypair<R: rand::CryptoRng + rand::Rng>(
        csprng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed = [0; 32];
        csprng
            .try_fill_bytes(&mut seed)
            .expect("seed of proper length");
        let dk = PrivateKey::from_bytes(&seed).expect("private key");
        let ek = Self::sk_to_pk(&dk);
        (dk, ek)
    }

    // NOTE: for implementation only
    // decap should happen from key
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        let encapped_key_bytes = encapped_key.to_bytes();
        let ct_pq_bytes: [u8; 1088] = encapped_key_bytes[..1088].try_into().expect("ct_pq length");
        let ct_pq: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_pq_bytes.into();
        let ct_t_bytes: [u8; 32] = encapped_key_bytes[1088..].try_into().expect("ct_t length");
        let ct_t = x25519_dalek::PublicKey::from(ct_t_bytes);

        let ss_pq = sk_recip.dk_pq.decapsulate(&ct_pq);
        let ss_t = sk_recip.dk_t.diffie_hellman(&ct_t);

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, &ss_t);
        Sha3Digest::update(&mut ss_hash, &ct_t);
        Sha3Digest::update(&mut ss_hash, pk_sender_id.unwrap().ek_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());
        Ok(ss)
    }

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::Rng>(
        pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        let (ct_pq, ss_pq) = pk_recip.ek_pq.encapsulate_with_rng(csprng);

        let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(csprng);
        let ct_t = x25519_dalek::PublicKey::from(&sk_e);
        let ss_t = sk_e.diffie_hellman(&pk_recip.ek_t);

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, ss_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, ct_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, pk_recip.ek_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());

        let mut ct = [0; 1120];
        ct[..1088].copy_from_slice(&ct_pq);
        ct[1088..].copy_from_slice(&ct_t.as_bytes()[..32]);
        let ek = Self::EncappedKey::from_bytes(&ct[..1120])?;

        Ok((ss, ek))
    }
}

struct YubiKeyMlKem768X25519<'a>(PhantomData<&'a ()>);

impl<'a> KemTrait for YubiKeyMlKem768X25519<'a> {
    type PublicKey = PublicKey;
    type PrivateKey = YubiKeyKemPrivateKey<'a, MlKem768X25519>;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(_: &Self::PrivateKey) -> Self::PublicKey {
        unreachable!("Never used")
    }

    fn derive_keypair(_: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        unreachable!("Never used")
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        _pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        let mut sk_recip = sk_recip.conn.write().unwrap();
        let dk_pq = PrivateKey::from_bytes(&sk_recip.seed())
            .expect("dk_pq from cert")
            .dk_pq;

        let encapped_key_bytes = encapped_key.to_bytes();
        let ct_pq_bytes: [u8; 1088] = encapped_key_bytes[..1088].try_into().expect("ct length");
        let ct_pq: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_pq_bytes.into();
        let ct_t: [u8; 32] = encapped_key_bytes[1088..].try_into().expect("ct length");

        let ss_pq = dk_pq.decapsulate(&ct_pq);
        let ss_t = match sk_recip.decrypt_data(&ct_t) {
            Ok(res) => res,
            Err(_) => return Err(hpke::HpkeError::DecapError),
        };

        let ek_t_bytes = sk_recip
            .cert()
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .unwrap();

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, &ss_t);
        Sha3Digest::update(&mut ss_hash, &ct_t);
        Sha3Digest::update(&mut ss_hash, &ek_t_bytes);
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());
        Ok(ss)
    }

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::Rng>(
        _: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        _: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        unreachable!("Never called")
    }
}

/// The non-hybrid tagged age recipient type, designed for hardware keys where decryption
/// potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Recipient(PublicKey);

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, &self.0.to_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Recipient {
    /// Attempts to parse a valid mlkem768x25519tag recipient.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: [u8; 1216] = bytes.try_into().expect("public key length");
        match PublicKey::from_bytes(&data) {
            Ok(pubkey) => Some(Self(pubkey)),
            _ => None,
        }
    }

    pub(crate) fn from(cert: &Certificate, seed: &[u8]) -> Option<Self> {
        let seed: [u8; 32] = seed.try_into().expect("seed length");
        let expanded_key = ExpandedKey::from(&seed);

        let mut ek_bytes = [0; 1216];
        ek_bytes[..1184].copy_from_slice(&expanded_key.ek_pq.to_bytes());
        ek_bytes[1184..].copy_from_slice(
            cert.cert
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes(),
        );
        let ek = PublicKey::from_bytes(&ek_bytes).expect("ek from bytes");
        Some(Self(ek))
    }

    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.0.ek_t.as_bytes())
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let mut csprng = rand::rng();
        let (enc, ct) = hpke_seal(
            &self.0,
            MLKEM768X25519TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut csprng,
        );

        RecipientLine {
            tag: tag(&enc, self.static_tag()),
            enc,
            ct,
        }
    }
}

fn tag(
    enc: &<MlKem768X25519 as hpke::Kem>::EncappedKey,
    static_tag: [u8; TAG_BYTES],
) -> [u8; TAG_BYTES] {
    let ikm = enc
        .to_bytes()
        .into_iter()
        .chain(static_tag)
        .collect::<Vec<u8>>();

    stanza_tag(&ikm, MLKEM768X25519TAG_SALT)
}

pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    enc: <MlKem768X25519 as hpke::Kem>::EncappedKey,
    ct: Vec<u8>,
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: MLKEM768X25519TAG_RECIPIENT_TAG.to_owned(),
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
        if s.tag != MLKEM768X25519TAG_RECIPIENT_TAG {
            return None;
        }

        let (tag, enc) = match &s.args[..] {
            [encoded_tag, encoded_enc] => (
                base64_arg(encoded_tag, [0; TAG_BYTES]),
                base64_arg(encoded_enc, [0; ENC_BYTES]).and_then(|bytes| {
                    <MlKem768X25519 as hpke::Kem>::EncappedKey::from_bytes(&bytes[..]).ok()
                }),
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
        assert_eq!(self.tag, tag(&self.enc, stub.tag));
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
        hpke_open::<YubiKeyMlKem768X25519>(
            &self.enc,
            &sk_recip,
            MLKEM768X25519TAG_SALT.as_bytes(),
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
