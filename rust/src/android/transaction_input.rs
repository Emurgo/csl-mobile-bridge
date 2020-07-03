use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobject, jint};
use jni::JNIEnv;
use cddl_lib::address::{StakeCredential};
use cddl_lib::crypto::{TransactionHash};
use cddl_lib::TransactionInput;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionInputToBytes(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_input = ptr.rptr(&env)?;
    tx_input
      .typed_ref::<TransactionInput>()
      .map(|tx_input| tx_input.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionInputFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| TransactionInput::from_bytes(bytes).into_result())
      .and_then(|tx_input| tx_input.rptr().jptr(&env))
  })
  .jresult(&env)
}

// TODO: consider using jlong instead of jint
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionInputNew(
  env: JNIEnv, _: JObject, transaction_hash: JRPtr, transaction_index: jint
) -> jobject {
  let transaction_hash = transaction_hash.owned::<TransactionHash>(&env);
  handle_exception_result(|| {
    TransactionInput::new(transaction_hash?, transaction_index as u32).rptr().jptr(&env)
  })
  .jresult(&env)
}
