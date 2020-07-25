use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::ptr_j::*;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{TransactionHash};
use cardano_serialization_lib::error::{DeserializeError};
use wasm_bindgen::JsValue;

impl ToFromBytes for TransactionHash {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionHash, DeserializeError> {
    TransactionHash::from_bytes(bytes)
  }

}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionHashToBytes(
  env: JNIEnv, _: JObject, transaction_hash: JRPtr
) -> jobject {
  to_bytes::<TransactionHash>(env, transaction_hash)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionHashFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<TransactionHash>(env, bytes)
}
