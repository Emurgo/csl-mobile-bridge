use super::primitive::ToPrimitiveObject;
use crate::utils::ToFromBytes;
use super::result::ToJniResult;
use super::utils::{to_bytes, from_bytes};
use super::ptr_j::*;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject, jint};
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

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyOutputs(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionBody>().and_then(|tx_body| tx_body.outputs().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyInputs(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionBody>().and_then(|tx_body| tx_body.inputs().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyFee(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionBody>().and_then(|tx_body| tx_body.fee().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyTtl(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.ttl())
      .and_then(|ttl| (ttl as jint).jobject(&env))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyCerts(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionBody>().and_then(|tx_body| tx_body.certs().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBodyWithdrawals(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<TransactionBody>().and_then(|tx_body| tx_body.withdrawals().rptr().jptr(&env))
  })
  .jresult(&env)
}
