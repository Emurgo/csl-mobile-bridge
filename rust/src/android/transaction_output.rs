use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobject, jlong};
use jni::JNIEnv;
use cddl_lib::address::{Address, StakeCredential};
use cddl_lib::crypto::{TransactionHash};
use cddl_lib::TransactionOutput;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionOutputToBytes(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_output = ptr.rptr(&env)?;
    tx_output
      .typed_ref::<TransactionOutput>()
      .map(|tx_output| tx_output.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionOutputFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| TransactionOutput::from_bytes(bytes).into_result())
      .and_then(|tx_output| tx_output.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_TransactionOutputNew(
  env: JNIEnv, _: JObject, address: JRPtr, amount: jlong
) -> jobject {
  let address = address.owned::<Address>(&env);
  let coin_u64 = u64::from_jlong(amount);
  handle_exception_result(|| {
    TransactionOutput::new(address?, coin_u64).rptr().jptr(&env)
  })
  .jresult(&env)
}
