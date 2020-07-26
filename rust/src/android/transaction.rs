use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::{Transaction, TransactionBody, TransactionWitnessSet, TransactionMetadata};

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
    let metadata = metadata.rptr(&env)?;
    body.typed_ref::<TransactionBody>()
    .zip(witness_set.typed_ref::<TransactionWitnessSet>())
    .zip(metadata.typed_ref::<TransactionMetadata>())
    .and_then(
      |((body, witness_set), metadata)| {
        Transaction::new(body, witness_set, Some(metadata)).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}
