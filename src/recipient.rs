use std::fmt;

use age_core::format::{FileKey, Stanza};
use sha2::{Digest, Sha256};

use crate::{
    native::{mlkem768p256tag, p256tag},
    piv_p256,
    util::Metadata,
    PLUGIN_NAME,
};

pub(crate) const TAG_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) enum Recipient {
    PivP256(piv_p256::Recipient),
    P256Tag(p256tag::Recipient),
    MlKem768P256Tag(Box<mlkem768p256tag::Recipient>),
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Recipient::PivP256(recipient) => recipient.fmt(f),
            Recipient::P256Tag(recipient) => recipient.fmt(f),
            Recipient::MlKem768P256Tag(recipient) => recipient.fmt(f),
        }
    }
}

impl Recipient {
    /// Attempts to parse a supported YubiKey recipient.
    pub(crate) fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        match plugin_name {
            PLUGIN_NAME => piv_p256::Recipient::from_bytes(bytes).map(Self::PivP256),
            p256tag::PLUGIN_NAME => p256tag::Recipient::from_bytes(bytes).map(Self::P256Tag),
            mlkem768p256tag::PLUGIN_NAME => mlkem768p256tag::Recipient::from_bytes(bytes)
                .map(Box::new)
                .map(Self::MlKem768P256Tag),
            _ => None,
        }
    }

    /// Helper for returning the legacy encoding of this recipient, if any.
    pub(crate) fn legacy_recipient(&self, metadata: &Metadata) -> Option<String> {
        metadata
            .is_pre_p256tag()
            .then(|| match self {
                Recipient::P256Tag(recipient) => Some(
                    piv_p256::Recipient::from_bytes(recipient.to_compressed().as_bytes())
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
            Recipient::MlKem768P256Tag(recipient) => recipient.static_tag(),
        }
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> Stanza {
        match self {
            Recipient::PivP256(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::P256Tag(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::MlKem768P256Tag(recipient) => recipient.wrap_file_key(file_key).into(),
        }
    }
}

pub(crate) fn static_tag(pk: &[u8]) -> [u8; TAG_BYTES] {
    Sha256::digest(pk)[0..TAG_BYTES]
        .try_into()
        .expect("length is correct")
}
