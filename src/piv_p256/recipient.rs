use age_core::primitives::bech32_encode_to_fmt;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};

use std::fmt;

use crate::recipient::{static_tag, TAG_BYTES};

const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1yubikey");

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
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, self.to_encoded().as_bytes())
    }
}

impl Recipient {
    /// Attempts to parse a valid YubiKey recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded = p256::Sec1Point::from_bytes(bytes).ok()?;
        if encoded.is_compressed() {
            Self::from_encoded(&encoded)
        } else {
            None
        }
    }

    /// Attempts to parse a valid YubiKey recipient from its SEC-1 encoding.
    ///
    /// This accepts both compressed (as used by the plugin) and uncompressed (as used in
    /// the YubiKey certificate) encodings.
    fn from_encoded(encoded: &p256::Sec1Point) -> Option<Self> {
        Option::from(p256::PublicKey::from_sec1_point(encoded)).map(Recipient)
    }

    /// Returns the compressed SEC-1 encoding of this recipient.
    pub(crate) fn to_encoded(&self) -> p256::Sec1Point {
        self.0.to_sec1_point(true)
    }

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.to_encoded().as_bytes())
    }

    /// Exposes the wrapped public key.
    pub(crate) fn public_key(&self) -> &p256::PublicKey {
        &self.0
    }
}
