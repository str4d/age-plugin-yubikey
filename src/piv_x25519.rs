use age_core::primitives::bech32_encode_to_fmt;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use yubikey::Certificate;

use std::fmt;

pub(crate) const TAG_BYTES: usize = 4;
pub(crate) const STANZA_TAG: &str = "piv-x25519";

const EPK_BYTES: usize = 32;
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"piv-x25519";

mod recipient;
pub(crate) use recipient::Recipient;
