use crate::KVObjectError;
use asymmetric_crypto::hasher::sha3::Sha3;
use asymmetric_crypto::keypair::Keypair;
use asymmetric_crypto::prelude::Certificate;
use asymmetric_crypto::{signature, CryptoError, NewU8129};
use dislog_hal::{Bytes, Hasher, Point, Scalar};
use dislog_hal_sm2::NewU833;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairSm2(
    pub Keypair<[u8; 32], Sha3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>,
);

impl asymmetric_crypto::prelude::Keypair for KeyPairSm2 {
    type Seed = [u8; 32];

    type Secret = Scalar<dislog_hal_sm2::ScalarInner>;

    type Public = Point<dislog_hal_sm2::PointInner>;

    type Code = [u8; 32];

    type Signature = signature::sm2::Signature<dislog_hal_sm2::ScalarInner>;

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
        signature::sm2::sm2_signature::<_, H, _, _, R>(hasher, &self.0.get_secret_key(), rng)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSm2(<KeyPairSm2 as asymmetric_crypto::prelude::Keypair>::Public);

impl Certificate for CertificateSm2 {
    type Signature = signature::sm2::Signature<dislog_hal_sm2::ScalarInner>;

    fn verify<H: Default + Hasher<Output = [u8; 32]> + Hasher>(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        let mut hasher = H::default();
        hasher.update(msg);
        signature::sm2::sm2_verify::<_, H, _, _>(hasher, &self.0, signature)
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

#[cfg(test)]
mod tests {
    use super::KeyPairSm2;
    use asymmetric_crypto::hasher::sm3::Sm3;
    use asymmetric_crypto::prelude::Certificate;
    use dislog_hal::Bytes;

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

        println!("sigture: {:?}", sig_info.to_bytes());

        let cert_sm2 = keypair_sm2.get_certificate();

        let ans = cert_sm2.verify::<Sm3>(&data_b[..], &sig_info);
        assert_eq!(ans, true);
    }
}
