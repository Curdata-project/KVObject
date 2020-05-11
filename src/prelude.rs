use crate::KVObjectError;
use core::fmt::Debug;
use dislog_hal::Bytes;
use serde::{Deserialize, Serialize};

pub trait AttrProxy {
    type Byte;

    // 根据key读取值
    fn get_key(&self, key: &str) -> Result<Self::Byte, KVObjectError>;

    // 根据key写取值
    fn set_key(&mut self, key: &str, value: &Self::Byte) -> Result<(), KVObjectError>;
}

pub trait KVObject: Serialize + for<'de> Deserialize<'de> + AttrProxy {
    type Bytes: Debug + AsRef<[u8]>;

    type Signature: Serialize + for<'de> Deserialize<'de> + Bytes;

    type KeyPair: asymmetric_crypto::prelude::Keypair<Signature = Self::Signature>;

    type Certificate: asymmetric_crypto::prelude::Certificate<Signature = Self::Signature>;

    // 从Bytes反序列化
    fn from_bytes(bytes: &Self::Bytes) -> Result<Self, KVObjectError>;

    // 序列化成Bytes
    fn to_bytes(&mut self, keypair: &Self::KeyPair) -> Result<Self::Bytes, KVObjectError>;
}
