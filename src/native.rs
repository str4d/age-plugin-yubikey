use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::RwLock;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::key::Connection;

pub(crate) mod mlkem768p256tag;
pub(crate) mod p256tag;

/// Derives a tag for the tagged age recipient formats.
fn stanza_tag(ikm: &[u8], salt: &str) -> [u8; 4] {
    let (tag, _) = Hkdf::<Sha256>::extract(Some(salt.as_bytes()), ikm);
    tag[..4].try_into().expect("correct length")
}

/// Pretend that a YubiKey connection is a KEM private key.
struct YubiKeyKemPrivateKey<'a, Kem> {
    conn: Rc<RwLock<&'a mut Connection>>,
    _kem: PhantomData<Kem>,
}

impl<'a, Kem> YubiKeyKemPrivateKey<'a, Kem> {
    fn new(conn: &'a mut Connection) -> Self {
        Self {
            conn: Rc::new(RwLock::new(conn)),
            _kem: PhantomData,
        }
    }
}

impl<'a, Kem> Clone for YubiKeyKemPrivateKey<'a, Kem> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            _kem: PhantomData,
        }
    }
}

impl<'a, Kem> PartialEq for YubiKeyKemPrivateKey<'a, Kem> {
    fn eq(&self, other: &Self) -> bool {
        self.conn.read().unwrap().stub() == other.conn.read().unwrap().stub()
    }
}
impl<'a, Kem> Eq for YubiKeyKemPrivateKey<'a, Kem> {}

impl<'a, Kem: hpke::Kem> hpke::Serializable for YubiKeyKemPrivateKey<'a, Kem> {
    type OutputSize = <Kem::PrivateKey as hpke::Serializable>::OutputSize;
    fn write_exact(&self, _: &mut [u8]) {
        unreachable!("Never called")
    }
}
impl<'a, Kem: hpke::Kem> hpke::Deserializable for YubiKeyKemPrivateKey<'a, Kem> {
    fn from_bytes(_: &[u8]) -> Result<Self, hpke::HpkeError> {
        unreachable!("Never called")
    }
}
