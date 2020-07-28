use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::ptr_j::*;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::{TransactionBody};
use cardano_serialization_lib::error::{DeserializeError};

impl ToFromBytes for TransactionBody {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionBody, DeserializeError> {
    TransactionBody::from_bytes(bytes)
  }

}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyToBytes(
  env: JNIEnv, _: JObject, transaction_body: JRPtr
) -> jobject {
  to_bytes::<TransactionBody>(env, transaction_body)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<TransactionBody>(env, bytes)
}
