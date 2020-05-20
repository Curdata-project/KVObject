use crate::prelude::{AttrProxy, KValueObject};
use crate::sm2::{CertificateSm2, KeyPairSm2};
use crate::KVObjectError;
use asymmetric_crypto::hasher::sm3::Sm3;
use asymmetric_crypto::prelude::{Certificate, Keypair};
use core::fmt::Debug;
use dislog_hal::Bytes;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

pub const MSGTYPE_LEN: usize = 1;
pub const MSGTYPE_OFFSET: usize = 0;
pub const MSGTYPE_END: usize = MSGTYPE_OFFSET + MSGTYPE_LEN;

pub const CERT_LEN: usize = 33;
pub const CERT_OFFSET: usize = MSGTYPE_END;
pub const CERT_END: usize = CERT_OFFSET + CERT_LEN;

pub const SIGTURE_LEN: usize = 64;
pub const SIGTURE_OFFSET: usize = CERT_END;
pub const SIGTURE_END: usize = SIGTURE_OFFSET + SIGTURE_LEN;

pub const HEAD_TOTAL_LEN: usize = MSGTYPE_LEN + CERT_LEN + SIGTURE_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MsgType {
    PREISSUE,
    ISSUE,
    Quota,
    Currency,
    QuotaRecycleReceipt,
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
            0x03 => Ok(MsgType::Quota),
            0x04 => Ok(MsgType::Currency),
            0x05 => Ok(MsgType::QuotaRecycleReceipt),
            _ => Err(KVObjectError::DeSerializeError),
        }
    }

    fn to_bytes(&self) -> Self::BytesType {
        Vec::<u8>::from(match self {
            MsgType::PREISSUE => [0x01],
            MsgType::ISSUE => [0x02],
            MsgType::Quota => [0x03],
            MsgType::Currency => [0x04],
            MsgType::QuotaRecycleReceipt => [0x05],
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

pub trait KVBody:
    Debug
    + Clone
    + Serialize
    + for<'de> Deserialize<'de>
    + Bytes<Error = KVObjectError>
    + AttrProxy<Byte = Vec<u8>>
{
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KVObject<T: KVBody> {
    msg_type: MsgType,
    cert: Option<CertificateSm2>,
    sigture: Option<<KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Signature>,
    #[serde(bound(deserialize = "T: KVBody"))]
    t_obj: T,
}

impl<T: KVBody> KVObject<T> {
    pub fn new(msg_type: MsgType, t_obj: T) -> Self {
        Self {
            msg_type,
            cert: None,
            sigture: None,
            t_obj,
        }
    }

    pub fn get_body(&self) -> &T {
        &self.t_obj
    }
}

impl<T: KVBody> Bytes for KVObject<T> {
    type BytesType = Vec<u8>;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, KVObjectError> {
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

        // 序列化结构体T
        let t_obj = T::from_bytes(&bytes[HEAD_TOTAL_LEN..])?;

        Ok(Self {
            msg_type,
            cert: Some(cert),
            sigture: Some(sigture),
            t_obj,
        })
    }

    fn to_bytes(&self) -> Self::BytesType {
        let mut ret = Vec::<u8>::new();

        ret.extend_from_slice(self.msg_type.to_bytes().as_ref());
        if let Some(cert) = &self.cert {
            ret.extend_from_slice(cert.to_bytes().as_ref());
        }
        if let Some(sigture) = &self.sigture {
            ret.extend_from_slice(sigture.to_bytes().as_ref());
        }
        ret.extend_from_slice(self.t_obj.to_bytes().as_ref());

        ret
    }
}

impl<T: KVBody> KValueObject for KVObject<T> {
    type KeyPair = KeyPairSm2;

    type Certificate = CertificateSm2;

    type Signature = <KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Signature;

    fn fill_kvhead(&mut self, keypair: &Self::KeyPair) -> Result<(), KVObjectError> {
        let body_ = self.t_obj.to_bytes();

        let sigture = keypair
            .sign::<Sm3, _>(body_.as_ref(), &mut thread_rng())
            .map_err(|_| KVObjectError::SerializeSignError)?;

        self.sigture = Some(sigture);
        self.cert = Some(keypair.get_certificate());

        Ok(())
    }

    fn verfiy_kvhead(&self) -> Result<(), KVObjectError> {
        // 根据证书链验证证书，略过
        // 根据证书验证签名
        if self.cert.is_none() || self.sigture.is_none() {
            return Err(KVObjectError::KVHeadVerifyError);
        }
        if let Some(cert) = &self.cert {
            if let Some(sigture) = &self.sigture {
                let isvalid = cert.verify::<Sm3>(self.t_obj.to_bytes().as_ref(), &sigture);
                if !isvalid {
                    return Err(KVObjectError::KVHeadVerifyError);
                }
            }
        }
        Ok(())
    }
}

impl<T: KVBody> AttrProxy for KVObject<T> {
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
