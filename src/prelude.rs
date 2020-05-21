use crate::KVObjectError;
use dislog_hal::Bytes;
use serde::{Deserialize, Serialize};

pub trait AttrProxy {
    type Byte;

    // 根据key读取值
    fn get_key(&self, key: &str) -> Result<Self::Byte, KVObjectError>;

    // 根据key写取值
    fn set_key(&mut self, key: &str, value: &Self::Byte) -> Result<(), KVObjectError>;
}

pub trait KValueObject: Serialize + for<'de> Deserialize<'de> + AttrProxy + Bytes {
    type Signature: Serialize + for<'de> Deserialize<'de> + Bytes;

    type KeyPair: asymmetric_crypto::prelude::Keypair<Signature = Self::Signature>;

    type Certificate: asymmetric_crypto::prelude::Certificate<Signature = Self::Signature>;

    fn fill_kvhead(&mut self, keypair: &Self::KeyPair) -> Result<(), KVObjectError>;

    fn verfiy_kvhead(&self) -> Result<(), KVObjectError>;
}
