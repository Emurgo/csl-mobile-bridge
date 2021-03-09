use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::utils::{BigNum};
use cardano_serialization_lib::metadata::{TransactionMetadatumLabels};

impl ToFromBytes for TransactionMetadatumLabels {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadatumLabels, DeserializeError> {
    TransactionMetadatumLabels::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsToBytes(
  env: JNIEnv, _: JObject, transaction_metadatum_labels: JRPtr
) -> jobject {
  to_bytes::<TransactionMetadatumLabels>(env, transaction_metadatum_labels)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<TransactionMetadatumLabels>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| TransactionMetadatumLabels::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsLen(
  env: JNIEnv, _: JObject, transaction_metadatum_labels: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let transaction_metadatum_labels = transaction_metadatum_labels.rptr(&env)?;
    transaction_metadatum_labels
      .typed_ref::<TransactionMetadatumLabels>()
      .map(|transaction_metadatum_labels| transaction_metadatum_labels.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsGet(
  env: JNIEnv, _: JObject, transaction_metadatum_labels: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let transaction_metadatum_labels = transaction_metadatum_labels.rptr(&env)?;
    transaction_metadatum_labels
      .typed_ref::<TransactionMetadatumLabels>()
      .map(|transaction_metadatum_labels| transaction_metadatum_labels.get(usize::from_jlong(index)))
      .and_then(|transaction_metadatum_label| transaction_metadatum_label.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumLabelsAdd(
  env: JNIEnv, _: JObject, transaction_metadatum_labels: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let transaction_metadatum_labels = transaction_metadatum_labels.rptr(&env)?;
    let item = item.rptr(&env)?;
    transaction_metadatum_labels
      .typed_ref::<TransactionMetadatumLabels>()
      .zip(item.typed_ref::<BigNum>())
      .map(|(transaction_metadatum_labels, item)| transaction_metadatum_labels.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
