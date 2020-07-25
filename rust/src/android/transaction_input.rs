use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobject, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::crypto::{TransactionHash};
use cardano_serialization_lib::TransactionInput;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionInputToBytes(
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionInputFromBytes(
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

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionInputTransactionId(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionInput>().and_then(|tx_input| tx_input.transaction_id().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionInputIndex(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<TransactionInput>()
      .map(|tx_input| tx_input.index())
      .and_then(|index| (index as jlong).jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionInputNew(
  env: JNIEnv, _: JObject, transaction_id: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let transaction_id = transaction_id.rptr(&env)?;
    transaction_id
      .typed_ref::<TransactionHash>()
      .map(|tx_hash| TransactionInput::new(tx_hash, index as u32))
      .and_then(|tx_input| tx_input.rptr().jptr(&env))
  })
  .jresult(&env)
}
