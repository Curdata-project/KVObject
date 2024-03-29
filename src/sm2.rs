use crate::KVObjectError;
use asymmetric_crypto::hasher::sha3::Sha3;
use asymmetric_crypto::keypair::Keypair;
use asymmetric_crypto::prelude::Certificate;
use asymmetric_crypto::{signature, CryptoError, NewU8129, NewU864};
use dislog_hal::{Bytes, Hasher, Point, Scalar};
use dislog_hal_sm2::NewU833;
use rand::RngCore;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use hex::{ToHex, FromHex};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Default, Debug, Clone)]
pub struct KeyPairSm2(
    pub Keypair<[u8; 32], Sha3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>,
);

impl asymmetric_crypto::prelude::Keypair for KeyPairSm2 {
    type Seed = [u8; 32];

    type Secret = Scalar<dislog_hal_sm2::ScalarInner>;

    type Public = Point<dislog_hal_sm2::PointInner>;

    type Code = [u8; 32];

    type Signature = SignatureSm2;

    type Certificate = CertificateSm2;

    fn generate<R: RngCore>(rng: &mut R) -> Result<Self, CryptoError> {
        match Keypair::generate::<R>(rng) {
            Ok(x) => Ok(Self(x)),
            Err(_) => Err(CryptoError::KeyPairGenError),
        }
    }

    fn generate_from_seed(seed: Self::Seed) -> Result<Self, CryptoError> {
        match Keypair::generate_from_seed(seed) {
            Ok(x) => Ok(Self(x)),
            Err(_) => Err(CryptoError::KeyPairGenError),
        }
    }

    fn sign<H: Default + Hasher<Output = [u8; 32]> + Hasher, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, CryptoError> {
        let mut hasher = H::default();
        hasher.update(msg);
        Ok(SignatureSm2(signature::sm2::sm2_signature::<_, H, _, _, R>(hasher, &self.0.get_secret_key(), rng)?))
    }

    fn get_certificate(&self) -> Self::Certificate {
        CertificateSm2(self.0.get_public_key())
    }
}

impl Bytes for KeyPairSm2 {
    type BytesType = NewU8129;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed.as_mut()[i] = bytes[i];
        }
        let pri_key = Scalar::<dislog_hal_sm2::ScalarInner>::from_bytes(&bytes[32..64])
            .map_err(|_| KVObjectError::DeSerializeError)?;
        let pub_key = Point::<dislog_hal_sm2::PointInner>::from_bytes(&bytes[64..97])
            .map_err(|_| KVObjectError::DeSerializeError)?;
        let mut code = [0u8; 32];
        for i in 0..32 {
            code.as_mut()[i] = bytes[97 + i];
        }
        Ok(Self(Keypair::<_, _, _, _>::new(
            seed, pub_key, pri_key, code,
        )))
    }

    fn to_bytes(&self) -> Self::BytesType {
        let mut ret = [0u8; 129];
        ret[0..32].clone_from_slice(self.0.get_seed().as_ref());
        ret[32..64].clone_from_slice(self.0.get_secret_key().to_bytes().as_ref());
        ret[64..97].clone_from_slice(self.0.get_public_key().to_bytes().as_ref());
        ret[97..129].clone_from_slice(self.0.get_seed().as_ref());

        NewU8129(ret)
    }
}

impl Serialize for KeyPairSm2 {
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serializer.serialize_str(&self.to_bytes().encode_hex_upper::<String>())
    }
}

impl<'de> Deserialize<'de> for KeyPairSm2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d_str = String::deserialize(deserializer)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        let d_byte = Vec::<u8>::from_hex(d_str)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        KeyPairSm2::from_bytes(d_byte.as_slice())
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct CertificateSm2(<KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Public);

impl Certificate for CertificateSm2 {
    type Signature = SignatureSm2;

    fn verify<H: Default + Hasher<Output = [u8; 32]> + Hasher>(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        let mut hasher = H::default();
        hasher.update(msg);
        signature::sm2::sm2_verify::<_, H, _, _>(hasher, &self.0, &signature.0)
    }
}

impl Default for CertificateSm2 {
    fn default() -> Self {
        Self(<KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Public::default())
    }
}

impl Bytes for CertificateSm2 {
    type BytesType = NewU833;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let a = <KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Public::from_bytes(bytes)
            .map_err(|_| KVObjectError::DeSerializeError)?;
        Ok(Self(a))
    }

    fn to_bytes(&self) -> Self::BytesType {
        self.0.to_bytes()
    }
}

impl Serialize for CertificateSm2 {
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serializer.serialize_str(&self.to_bytes().encode_hex_upper::<String>())
    }
}

impl<'de> Deserialize<'de> for CertificateSm2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d_str = String::deserialize(deserializer)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        let d_byte = Vec::<u8>::from_hex(d_str)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        CertificateSm2::from_bytes(d_byte.as_slice())
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))
    }
}

#[derive(Debug, Clone)]
pub struct SignatureSm2(pub signature::sm2::Signature<dislog_hal_sm2::ScalarInner>);

impl Default for SignatureSm2 {
    fn default() -> Self {
        Self(signature::sm2::Signature::<dislog_hal_sm2::ScalarInner>::default())
    }
}

impl Bytes for SignatureSm2 {
    type BytesType = NewU864;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(signature::sm2::Signature::<dislog_hal_sm2::ScalarInner>::from_bytes(bytes).map_err(|_| KVObjectError::DeSerializeError)?))
    }

    fn to_bytes(&self) -> Self::BytesType {
        self.0.to_bytes()
    }
}

impl Serialize for SignatureSm2 {
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serializer.serialize_str(&self.to_bytes().encode_hex_upper::<String>())
    }
}

impl<'de> Deserialize<'de> for SignatureSm2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let d_str = String::deserialize(deserializer)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        let d_byte = Vec::<u8>::from_hex(d_str)
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))?;
        SignatureSm2::from_bytes(d_byte.as_slice())
            .map_err(|_| serde::de::Error::custom(format_args!("invalid hex string")))
    }
}

#[cfg(test)]
mod tests {
    use super::KeyPairSm2;
    use asymmetric_crypto::hasher::sm3::Sm3;
    use asymmetric_crypto::prelude::Certificate;

    #[test]
    fn it_works() {
        use asymmetric_crypto::prelude::Keypair;
        use rand::thread_rng;

        let data_b = [
            34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255,
        ];

        let mut rng = thread_rng();
        let keypair_sm2: KeyPairSm2 = KeyPairSm2::generate(&mut rng).unwrap();

        let sig_info = keypair_sm2
            .sign::<Sm3, _>(&data_b[..], &mut thread_rng())
            .unwrap();

        let cert_sm2 = keypair_sm2.get_certificate();

        let ans = cert_sm2.verify::<Sm3>(&data_b[..], &sig_info);
        assert_eq!(ans, true);
    }
}
