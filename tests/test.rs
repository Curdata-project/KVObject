use asymmetric_crypto::prelude::Keypair;
use core::fmt::Debug;
use dislog_hal::Bytes;
use kv_object::kv_object::MsgType;
use kv_object::kv_object::{get_msgtpye, KVBody, KVObject};
use kv_object::prelude::{AttrProxy, KValueObject};
use kv_object::sm2::KeyPairSm2;
use kv_object::KVObjectError;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPoint {
    pub x: i32,
    pub y: i32,
}

impl Bytes for TestPoint {
    type BytesType = Vec<u8>;

    type Error = KVObjectError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 8 {
            return Err(KVObjectError::DeSerializeError);
        }
        let mut x_ = [0u8; 4];
        let mut y_ = [0u8; 4];
        x_.clone_from_slice(&bytes[..4]);
        y_.clone_from_slice(&bytes[4..8]);
        Ok(Self {
            x: i32::from_le_bytes(x_),
            y: i32::from_le_bytes(y_),
        })
    }

    fn to_bytes(&self) -> Self::BytesType {
        let mut ret = Vec::<u8>::new();
        ret.extend_from_slice(&self.x.to_le_bytes()[..]);
        ret.extend_from_slice(&self.y.to_le_bytes()[..]);

        ret
    }
}

impl AttrProxy for TestPoint {
    type Byte = Vec<u8>;

    // 根据key读取值
    fn get_key(&self, key: &str) -> Result<Self::Byte, KVObjectError> {
        let mut ret = Vec::<u8>::new();
        let x_ = self.x.clone().to_le_bytes();
        let y_ = self.y.clone().to_le_bytes();
        ret.extend_from_slice(match key {
            "x" => x_.as_ref(),
            "y" => y_.as_ref(),
            _ => return Err(KVObjectError::KeyIndexError),
        });
        Ok(ret)
    }

    // 根据key取值
    fn set_key(&mut self, key: &str, value: &Self::Byte) -> Result<(), KVObjectError> {
        if value.len() != 4 {
            return Err(KVObjectError::ValueValid);
        }

        let mut a_ = [0u8; 4];
        a_.clone_from_slice(&value[..]);
        let a = i32::from_le_bytes(a_);

        let field_ = match key {
            "x" => &mut self.x,
            "y" => &mut self.y,
            _ => return Err(KVObjectError::KeyIndexError),
        };
        *field_ = a;

        return Ok(());
    }
}

impl KVBody for TestPoint {}

type NewPoint = KVObject<TestPoint>;

#[test]
fn test_json_object() {
    let point = TestPoint { x: 1, y: 2 };

    let serialized = serde_json::to_string(&point).unwrap();
    println!("serialized = {}", serialized);

    let deserialized: TestPoint = serde_json::from_str(&serialized).unwrap();
    println!("deserialized = {:?}", deserialized);
}

#[test]
fn test_kvwrapper() {
    let mut rng = thread_rng();
    let keypair_sm2: KeyPairSm2 = KeyPairSm2::generate(&mut rng).unwrap();

    let mut point = NewPoint::new(MsgType::PREISSUE, TestPoint { x: 3, y: 5 });

    //let box_point = Box::new(point);

    let sign_bytes = point.to_bytes(&keypair_sm2).unwrap();

    println!("sigture: {:?}", sign_bytes);

    let mut point_1 = NewPoint::from_bytes(&sign_bytes).unwrap();

    println!("{:?}", point_1);

    assert_eq!(
        Vec::<u8>::from([3, 0, 0, 0].as_ref()),
        point_1.get_key("x").unwrap()
    );
    assert_eq!(
        Vec::<u8>::from([5, 0, 0, 0].as_ref()),
        point_1.get_key("y").unwrap()
    );

    point_1
        .set_key("x", &Vec::<u8>::from([7, 0, 0, 0].as_ref()))
        .unwrap();
    point_1
        .set_key("y", &Vec::<u8>::from([9, 0, 0, 0].as_ref()))
        .unwrap();

    assert_eq!(
        Vec::<u8>::from([7, 0, 0, 0].as_ref()),
        point_1.get_key("x").unwrap()
    );
    assert_eq!(
        Vec::<u8>::from([9, 0, 0, 0].as_ref()),
        point_1.get_key("y").unwrap()
    );

    let sign_point_1 = point_1.to_bytes(&keypair_sm2).unwrap();

    println!("{:?}", sign_point_1);

    assert_eq!(
        match get_msgtpye(&sign_point_1).unwrap() {
            MsgType::PREISSUE => "right type",
            _ => panic!(),
        },
        "right type"
    );

    let point_2 = NewPoint::from_bytes(&sign_point_1).unwrap();

    println!("{:?}", point_2);
    assert_eq!(
        Vec::<u8>::from([7, 0, 0, 0].as_ref()),
        point_1.get_key("x").unwrap()
    );
    assert_eq!(
        Vec::<u8>::from([9, 0, 0, 0].as_ref()),
        point_1.get_key("y").unwrap()
    );
}
