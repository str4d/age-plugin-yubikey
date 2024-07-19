use age_core::primitives::bech32_encode_to_fmt;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use yubikey::Certificate;

use std::fmt;

use crate::recipient::TAG_BYTES;

const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tag");

#[derive(Clone)]
pub struct Recipient(PublicKey);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({:?})", self)
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, self.0.as_bytes())
    }
}

impl Recipient {
    /// Attempts to parse a valid YubiKey recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: [u8; 32] = bytes.try_into().expect("correct key length");
        match PublicKey::try_from(data) {
            Ok(pubkey) => Some(Self(pubkey)),
            _ => None,
        }
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        let pk_data: [u8; 32] = spki
            .subject_public_key
            .raw_bytes()
            .try_into()
            .expect("spki bytes");
        Some(Self(x25519_dalek::PublicKey::from(pk_data)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        let tag = Sha256::digest(self.0.as_bytes());
        (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
    }

    /// Exposes the wrapped public key.
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.0
    }
}
