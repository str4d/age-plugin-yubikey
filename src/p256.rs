use bech32::{ToBase32, Variant};
use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    pkcs8::SubjectPublicKeyInfoRef,
};
use sha2::{Digest, Sha256};
use yubikey::Certificate;

use std::fmt;

use crate::RECIPIENT_PREFIX;

pub(crate) const TAG_BYTES: usize = 4;

/// Wrapper around a compressed secp256r1 curve point.
#[derive(Clone)]
pub struct Recipient(p256::PublicKey);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({:?})", self.to_encoded().as_bytes())
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(
                RECIPIENT_PREFIX,
                self.to_encoded().as_bytes().to_base32(),
                Variant::Bech32,
            )
            .expect("HRP is valid")
            .as_str(),
        )
    }
}

impl Recipient {
    /// Attempts to parse a valid YubiKey recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded = p256::EncodedPoint::from_bytes(bytes).ok()?;
        if encoded.is_compressed() {
            Self::from_encoded(&encoded)
        } else {
            None
        }
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        // TODO: https://github.com/RustCrypto/formats/issues/1604
        p256::PublicKey::try_from(spki).ok().map(Recipient)
    }

    /// Attempts to parse a valid YubiKey recipient from its SEC-1 encoding.
    ///
    /// This accepts both compressed (as used by the plugin) and uncompressed (as used in
    /// the YubiKey certificate) encodings.
    fn from_encoded(encoded: &p256::EncodedPoint) -> Option<Self> {
        Option::from(p256::PublicKey::from_encoded_point(encoded)).map(Recipient)
    }

    /// Returns the compressed SEC-1 encoding of this recipient.
    pub(crate) fn to_encoded(&self) -> p256::EncodedPoint {
        self.0.to_encoded_point(true)
    }

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        let tag = Sha256::digest(self.to_encoded().as_bytes());
        (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
    }

    /// Exposes the wrapped public key.
    pub(crate) fn public_key(&self) -> &p256::PublicKey {
        &self.0
    }
}
