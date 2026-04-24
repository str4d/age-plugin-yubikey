use std::fmt;

use age_core::format::{FileKey, Stanza};
use sha2::{Digest, Sha256};
use x509_cert::spki::SubjectPublicKeyInfoRef;
use yubikey::piv::AlgorithmId;

use crate::{
    native::{self, p256tag, x25519tag},
    piv_p256, piv_x25519,
    util::Metadata,
    PLUGIN_NAME,
};

pub(crate) const TAG_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) enum Recipient {
    PivP256(piv_p256::Recipient),
    P256Tag(p256tag::Recipient),
    PivX25519(piv_x25519::Recipient),
    X25519Tag(x25519tag::Recipient),
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Recipient::PivP256(recipient) => recipient.fmt(f),
            Recipient::P256Tag(recipient) => recipient.fmt(f),
            Recipient::PivX25519(recipient) => recipient.fmt(f),
            Recipient::X25519Tag(recipient) => recipient.fmt(f),
        }
    }
}

impl Recipient {
    /// Attempts to parse a supported YubiKey recipient.
    pub(crate) fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        match plugin_name {
            PLUGIN_NAME => {
                if bytes.len() == 32 {
                    piv_x25519::Recipient::from_bytes(bytes).map(Self::PivX25519)
                } else {
                    piv_p256::Recipient::from_bytes(bytes).map(Self::PivP256)
                }
            }
            native::PLUGIN_NAME => {
                if bytes.len() == 32 {
                    x25519tag::Recipient::from_bytes(bytes).map(Self::X25519Tag)
                } else {
                    p256tag::Recipient::from_bytes(bytes).map(Self::P256Tag)
                }
            }
            _ => None,
        }
    }

    pub(crate) fn algorithm(&self) -> AlgorithmId {
        match self {
            Self::PivP256(_) | Self::P256Tag(_) => AlgorithmId::EccP256,
            Self::PivX25519(_) | Self::X25519Tag(_) => AlgorithmId::X25519,
        }
    }

    pub(crate) fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        match spki.algorithm.oid {
            p256tag::OID_P256 => p256tag::Recipient::from_spki(spki).map(Self::P256Tag),
            x25519tag::OID_X25519 => x25519tag::Recipient::from_spki(spki).map(Self::X25519Tag),
            _ => None,
        }
    }

    /// Helper for returning the legacy encoding of this recipient, if any.
    pub(crate) fn legacy_recipient(&self, metadata: &Metadata) -> Option<String> {
        metadata
            .is_pre_native_tag()
            .then(|| match self {
                Recipient::P256Tag(recipient) => Some(
                    piv_p256::Recipient::from_bytes(recipient.to_compressed().as_bytes())
                        .expect("valid")
                        .to_string(),
                ),
                Recipient::X25519Tag(recipient) => Some(
                    piv_x25519::Recipient::from_bytes(&recipient.to_bytes())
                        .expect("valid")
                        .to_string(),
                ),
                _ => None,
            })
            .flatten()
    }

    /// Returns the static tag for this recipient.
    pub(crate) fn static_tag(&self) -> [u8; TAG_BYTES] {
        match self {
            Recipient::PivP256(recipient) => recipient.tag(),
            Recipient::P256Tag(recipient) => recipient.static_tag(),
            Recipient::PivX25519(recipient) => recipient.tag(),
            Recipient::X25519Tag(recipient) => recipient.static_tag(),
        }
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> Stanza {
        match self {
            Recipient::PivP256(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::P256Tag(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::PivX25519(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::X25519Tag(recipient) => recipient.wrap_file_key(file_key).into(),
        }
    }
}

pub(crate) fn static_tag(pk: &[u8]) -> [u8; TAG_BYTES] {
    Sha256::digest(pk)[0..TAG_BYTES]
        .try_into()
        .expect("length is correct")
}
