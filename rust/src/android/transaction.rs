use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::{Transaction, TransactionBody, TransactionWitnessSet};
use cardano_serialization_lib::metadata::TransactionMetadata;
use cardano_serialization_lib::error::{DeserializeError};

impl ToFromBytes for Transaction {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Transaction, DeserializeError> {
    Transaction::from_bytes(bytes)
  }

}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionToBytes(
  env: JNIEnv, _: JObject, transaction: JRPtr
) -> jobject {
  to_bytes::<Transaction>(env, transaction)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<Transaction>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBody(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<Transaction>().and_then(|tx| tx.body().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionNew(
  env: JNIEnv, _: JObject, body: JRPtr, witness_set: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let body = body.rptr(&env)?;
    let witness_set = witness_set.rptr(&env)?;
    body.typed_ref::<TransactionBody>().zip(witness_set.typed_ref::<TransactionWitnessSet>()).and_then(
      |(body, witness_set)| {
        Transaction::new(body, witness_set, None).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionNewWithMetadata(
  env: JNIEnv, _: JObject, body: JRPtr, witness_set: JRPtr, metadata: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let body = body.rptr(&env)?;
    let witness_set = witness_set.rptr(&env)?;
    let metadata = metadata.owned::<TransactionMetadata>(&env);
    body.typed_ref::<TransactionBody>()
    .zip(witness_set.typed_ref::<TransactionWitnessSet>())
    .and_then(
      |(body, witness_set)| {
        Transaction::new(body, witness_set, Some(metadata?)).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}
