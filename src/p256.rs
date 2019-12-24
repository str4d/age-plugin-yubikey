use elliptic_curve::sec1::EncodedPoint;
use p256::NistP256;
use std::fmt;

/// Wrapper around a compressed secp256r1 curve point.
#[derive(Clone)]
pub struct PublicKey(EncodedPoint<NistP256>);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({:?})", self.as_bytes())
    }
}

impl PublicKey {
    /// Attempts to parse a valid secp256r1 public key from a byte slice.
    ///
    /// The slice must contain an SEC-1-encoded public key.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_pubkey(EncodedPoint::from_bytes(bytes).ok()?)
    }

    /// Attempts to parse a valid secp256r1 public key from its SEC-1 encoding.
    pub(crate) fn from_pubkey(pubkey: EncodedPoint<NistP256>) -> Option<Self> {
        if pubkey.is_compressed() {
            if pubkey.decompress().is_some().into() {
                Some(PublicKey(pubkey))
            } else {
                None
            }
        } else {
            Some(PublicKey(pubkey.compress()))
        }
    }

    /// Returns the compressed SEC-1 encoding of this public key.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the uncompressed SEC-1 encoding of this public key.
    pub(crate) fn decompress(&self) -> EncodedPoint<NistP256> {
        self.0.decompress().unwrap()
    }
}
