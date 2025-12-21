use std::fmt;

use age_core::{
    format::{FileKey, Stanza},
    primitives::{bech32_encode_to_fmt, hpke_open, hpke_seal},
    secrecy::{zeroize::Zeroize, ExposeSecret},
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use hpke::{Deserializable, Serializable};
use ml_kem::{KemCore, MlKem768, MlKem768Params};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::rngs::OsRng;
use typenum::Unsigned;
use x509_parser::der_parser::Oid;
use yubikey::{certificate::PublicKeyInfo, Certificate};

use crate::{
    key::{self, Connection},
    native::{stanza_tag, YubiKeyKemPrivateKey},
    recipient::{static_tag, TAG_BYTES},
    util::base64_arg,
};

mod kem;

pub(crate) const PLUGIN_NAME: &str = "tagpq";
const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tagpq");

const MLKEM768P256TAG_RECIPIENT_TAG: &str = "mlkem768p256tag";
const MLKEM768P256TAG_SALT: &str = "age-encryption.org/mlkem768p256tag";

/// A 64-byte ML-KEM 768 seed, encoded as a DER Octet String in an X.509v3 critical
/// extension.
///
/// YubiKeys don't yet support ML-KEM internally, but we want the physical YubiKey to be
/// the only thing a user needs in order to decrypt age ciphertexts. We therefore need to
/// store the ML-KEM 768 seed somewhere in the YubiKey's publicly-reachable data. The only
/// place we can store arbitrary slot-specific data is in the slot's certificate, so we
/// use a custom extension.
pub(crate) const ML_KEM_768_SEED_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 64829, 1, 1];

type Kem = kem::MlKem768P256;
pub(crate) type PqPrivateKey = ml_kem::kem::DecapsulationKey<MlKem768Params>;

pub(crate) fn expand_pq_key(
    seed: &[u8; 64],
) -> (
    <MlKem768 as KemCore>::DecapsulationKey,
    <MlKem768 as KemCore>::EncapsulationKey,
) {
    let mut d = [0; 32];
    let mut z = [0; 32];
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);

    let (dk_pq, ek_pq) = MlKem768::generate_deterministic(&d.into(), &z.into());

    d.zeroize();
    z.zeroize();

    (dk_pq, ek_pq)
}

pub(crate) fn encode_ml_kem_768_seed<T>(
    dk_seed: &[u8; 64],
    f: impl FnOnce(x509::Extension<&'static [u64]>) -> T,
) -> T {
    let (value, _) = x509::der::write::der_octet_string(dk_seed)((vec![]).into())
        .expect("can write to vec")
        .into_inner();
    f(x509::Extension::critical(
        ML_KEM_768_SEED_EXTENSION_OID,
        &value,
    ))
}

pub(crate) fn extract_ml_kem_768_seed(cert: &Certificate) -> Option<[u8; 64]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;

    cert.tbs_certificate
        .get_extension_unique(&Oid::from(ML_KEM_768_SEED_EXTENSION_OID).unwrap())
        .ok()
        .flatten()
        .and_then(|ext| x509_parser::der_parser::parse_der(ext.value).ok())
        .and_then(|(rest, data)| {
            rest.is_empty()
                .then(|| match data.content {
                    x509_parser::der_parser::ber::BerObjectContent::OctetString(bytes) => {
                        bytes.try_into().ok()
                    }
                    _ => None,
                })
                .flatten()
        })
}

/// The non-hybrid tagged age recipient type, designed for hardware keys where decryption
/// potentially requires user presence.
///
/// With knowledge of the recipient, it is possible to check if a stanza was addressed to
/// a specific recipient before attempting decryption. This offers less privacy than the
/// untagged recipient types.
#[derive(Clone, PartialEq)]
pub(crate) struct Recipient(<Kem as hpke::Kem>::PublicKey);

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
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .ok()
            .map(Self)
    }

    pub(crate) fn from_certificate(
        cert: &Certificate,
    ) -> Option<(Self, <MlKem768 as KemCore>::DecapsulationKey)> {
        if let Some(dk_seed) = extract_ml_kem_768_seed(cert) {
            let (dk_pq, ek_pq) = expand_pq_key(&dk_seed);
            Self::from_spki(cert.subject_pki(), ek_pq).map(|r| (r, dk_pq))
        } else {
            None
        }
    }

    pub(crate) fn from_spki(
        spki: &PublicKeyInfo,
        ek_pq: <MlKem768 as KemCore>::EncapsulationKey,
    ) -> Option<Self> {
        let encoded = match spki {
            PublicKeyInfo::EcP256(pubkey) => Some(pubkey),
            _ => None,
        }?;

        let ek_t = p256::PublicKey::from_encoded_point(encoded).into_option()?;

        Some(Self(kem::PublicKey { ek_pq, ek_t }))
    }

    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.0.ek_t.to_encoded_point(false).as_bytes())
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let (enc, ct) = hpke_seal::<Kem, _>(
            &self.0,
            MLKEM768P256TAG_SALT.as_bytes(),
            file_key.expose_secret(),
            &mut OsRng,
        );

        RecipientLine {
            tag: tag(&enc, self.static_tag()),
            enc: Box::new(enc),
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

    stanza_tag(&ikm, MLKEM768P256TAG_SALT)
}

pub(crate) struct RecipientLine {
    tag: [u8; TAG_BYTES],
    enc: Box<<Kem as hpke::Kem>::EncappedKey>,
    ct: Vec<u8>,
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: MLKEM768P256TAG_RECIPIENT_TAG.to_owned(),
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
        if s.tag != MLKEM768P256TAG_RECIPIENT_TAG {
            return None;
        }

        let (tag, enc) = match &s.args[..] {
            [encoded_tag, encoded_enc] => (
                base64_arg(encoded_tag, [0; TAG_BYTES]),
                base64_arg(
                    encoded_enc,
                    [0; <kem::EncappedKey as Serializable>::OutputSize::USIZE],
                )
                .and_then(|bytes| {
                    <Kem as hpke::Kem>::EncappedKey::from_bytes(&bytes[..])
                        .ok()
                        .map(Box::new)
                }),
            ),
            _ => (None, None),
        };

        Some(match (tag, enc) {
            (Some(tag), Some(enc)) => Ok(RecipientLine {
                tag,
                enc,
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
        hpke_open::<kem::YubiKeyMlKem768P256>(
            &self.enc,
            &sk_recip,
            MLKEM768P256TAG_SALT.as_bytes(),
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
