use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};

pub trait HashType {
  fn to_bytes(&self) -> Vec<u8>;
  fn from_bytes(bytes: Vec<u8>) -> Result<Self, DeserializeError> where Self: Sized;
}

pub unsafe fn hash_to_bytes<T: RPtrRepresentable + HashType>(
  env: JNIEnv, hash: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let hash = hash.rptr(&env)?;
    hash
      .typed_ref::<T>()
      .map(|hash| hash.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

pub unsafe fn hash_from_bytes<T: RPtrRepresentable + HashType>(
  env: JNIEnv, bytes: jbyteArray,
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| T::from_bytes(bytes).into_result())
      .and_then(|hash| hash.rptr().jptr(&env))
  })
  .jresult(&env)
}
