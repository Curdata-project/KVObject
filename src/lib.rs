pub mod kv_object;

pub mod prelude;

pub mod sm2;

use core::fmt::Debug;
#[derive(Debug)]
pub enum KVObjectError {
    FindTypeError,
    SerializeError,
    SerializeSignError,
    DeSerializeError,
    DeSerializeVerifyError,
    KeyIndexError,
    ValueValid,
}
