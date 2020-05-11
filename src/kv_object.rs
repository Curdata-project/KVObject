use crate::prelude::{AttrProxy, KVObject};
use crate::sm2::{CertificateSm2, KeyPairSm2};
use crate::KVObjectError;
use asymmetric_crypto::hasher::sm3::Sm3;
use asymmetric_crypto::prelude::{Certificate, Keypair};
use core::fmt::Debug;
use dislog_hal::Bytes;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

const MSGTYPE_LEN: usize = 1;
const MSGTYPE_OFFSET: usize = 0;
const MSGTYPE_END: usize = MSGTYPE_OFFSET + MSGTYPE_LEN;

const CERT_LEN: usize = 33;
const CERT_OFFSET: usize = MSGTYPE_END;
const CERT_END: usize = CERT_OFFSET + CERT_LEN;

const SIGTURE_LEN: usize = 64;
const SIGTURE_OFFSET: usize = CERT_END;
const SIGTURE_END: usize = SIGTURE_OFFSET + SIGTURE_LEN;

const HEAD_TOTAL_LEN: usize = MSGTYPE_LEN + CERT_LEN + SIGTURE_LEN;

#[derive(Debug, Serialize, Deserialize)]
pub enum MsgType {
    PREISSUE,
    ISSUE,
}

impl Bytes for MsgType {
    type BytesType = Vec<u8>;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < MSGTYPE_LEN {
            return Err(KVObjectError::DeSerializeError);
        }
        match bytes[0] {
            0x01 => Ok(MsgType::PREISSUE),
            0x02 => Ok(MsgType::ISSUE),
            _ => Err(KVObjectError::DeSerializeError),
        }
    }

    fn to_bytes(&self) -> Self::BytesType {
        Vec::<u8>::from(match self {
            MsgType::PREISSUE => [0x01],
            MsgType::ISSUE => [0x02],
        })
    }
}

pub fn get_msgtpye(data: &[u8]) -> Result<MsgType, KVObjectError> {
    if data.len() < MSGTYPE_LEN {
        return Err(KVObjectError::FindTypeError);
    }

    MsgType::from_bytes(&data[MSGTYPE_OFFSET..MSGTYPE_END])
        .map_err(|_| KVObjectError::FindTypeError)
}

pub trait KVWrapperT:
    Serialize + for<'de> Deserialize<'de> + Bytes<Error = KVObjectError> + AttrProxy<Byte = Vec<u8>>
{
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KvWrapper<T: KVWrapperT> {
    msg_type: MsgType,
    cert: Option<CertificateSm2>,
    sigture: Option<<KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Signature>,
    #[serde(bound(deserialize = "T: KVWrapperT"))]
    t_obj: T,
}

impl<T: KVWrapperT> KvWrapper<T> {
    pub fn new(msg_type: MsgType, t_obj: T) -> Self {
        Self {
            msg_type,
            cert: None,
            sigture: None,
            t_obj,
        }
    }
}

impl<T: KVWrapperT> KVObject for KvWrapper<T> {
    type Bytes = Vec<u8>;

    type KeyPair = KeyPairSm2;

    type Certificate = CertificateSm2;

    type Signature = <KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Signature;

    // 从Bytes反序列化
    fn from_bytes(bytes: &Self::Bytes) -> Result<Self, KVObjectError> {
        if bytes.len() < HEAD_TOTAL_LEN {
            return Err(KVObjectError::DeSerializeError);
        }
        let msg_type = MsgType::from_bytes(&bytes[MSGTYPE_OFFSET..MSGTYPE_END])
            .map_err(|_| KVObjectError::DeSerializeError)?;
        let cert = CertificateSm2::from_bytes(&bytes[CERT_OFFSET..CERT_END])
            .map_err(|_| KVObjectError::DeSerializeError)?;
        let sigture = <KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Signature::from_bytes(
            &bytes[SIGTURE_OFFSET..SIGTURE_END],
        )
        .map_err(|_| KVObjectError::DeSerializeError)?;

        if bytes.len() == HEAD_TOTAL_LEN {
            return Err(KVObjectError::DeSerializeError);
        }

        // 根据证书链验证证书，略过
        // 根据证书验证签名
        let isvalid = cert.verify::<Sm3>(&bytes[HEAD_TOTAL_LEN..], &sigture);
        if isvalid == false {
            return Err(KVObjectError::DeSerializeVerifyError);
        }
        // 序列化结构体T
        let t_obj = T::from_bytes(&bytes[HEAD_TOTAL_LEN..])?;

        Ok(Self {
            msg_type,
            cert: Some(cert),
            sigture: Some(sigture),
            t_obj,
        })
    }

    // 序列化成Bytes
    fn to_bytes(&mut self, keypair: &Self::KeyPair) -> Result<Self::Bytes, KVObjectError> {
        let mut ret = Vec::<u8>::new();
        let body_ = self.t_obj.to_bytes();

        let sigture = keypair
            .sign::<Sm3, _>(body_.as_ref(), &mut thread_rng())
            .map_err(|_| KVObjectError::SerializeSignError)?;
        self.sigture = Some(sigture);
        self.cert = Some(keypair.gen_certificate());

        ret.extend_from_slice(self.msg_type.to_bytes().as_ref());
        if let Some(cert) = &self.cert {
            ret.extend_from_slice(cert.to_bytes().as_ref());
        }
        if let Some(sigture) = &self.sigture {
            ret.extend_from_slice(sigture.to_bytes().as_ref());
        }
        ret.extend_from_slice(body_.as_ref());

        Ok(ret)
    }
}

impl<T: KVWrapperT> AttrProxy for KvWrapper<T> {
    type Byte = Vec<u8>;

    // 根据key读取值
    fn get_key(&self, key: &str) -> Result<Self::Byte, KVObjectError> {
        self.t_obj.get_key(key)
    }

    // 根据key写取值
    fn set_key(&mut self, key: &str, value: &Self::Byte) -> Result<(), KVObjectError> {
        self.t_obj.set_key(key, value)
    }
}
