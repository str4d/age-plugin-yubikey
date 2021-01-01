use bech32::ToBase32;
use elliptic_curve::sec1::EncodedPoint;
use p256::NistP256;
use std::fmt;

use crate::RECIPIENT_PREFIX;

/// Wrapper around a compressed secp256r1 curve point.
#[derive(Clone)]
pub struct Recipient(EncodedPoint<NistP256>);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({:?})", self.as_bytes())
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(RECIPIENT_PREFIX, self.as_bytes().to_base32())
                .expect("HRP is valid")
                .as_str(),
        )
    }
}

impl Recipient {
    /// Attempts to parse a valid secp256r1 public key from its SEC-1 encoding.
    pub(crate) fn from_pubkey(pubkey: EncodedPoint<NistP256>) -> Option<Self> {
        if pubkey.is_compressed() {
            if pubkey.decompress().is_some().into() {
                Some(Recipient(pubkey))
            } else {
                None
            }
        } else {
            Some(Recipient(pubkey.compress()))
        }
    }

    /// Returns the compressed SEC-1 encoding of this public key.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
