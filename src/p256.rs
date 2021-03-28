use bech32::{ToBase32, Variant};
use elliptic_curve::sec1::EncodedPoint;
use p256::NistP256;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fmt;

use crate::RECIPIENT_PREFIX;

pub(crate) const TAG_BYTES: usize = 4;

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
            bech32::encode(
                RECIPIENT_PREFIX,
                self.as_bytes().to_base32(),
                Variant::Bech32,
            )
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

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        let tag = Sha256::digest(self.to_string().as_bytes());
        (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
    }
}
