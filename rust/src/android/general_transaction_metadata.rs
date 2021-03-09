use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{GeneralTransactionMetadata, TransactionMetadatum};
use cardano_serialization_lib::utils::{BigNum};

pub type TransactionMetadatumLabel = BigNum;

impl ToFromBytes for GeneralTransactionMetadata {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<GeneralTransactionMetadata, DeserializeError> {
    GeneralTransactionMetadata::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataToBytes(
  env: JNIEnv, _: JObject, general_transaction_metadata: JRPtr
) -> jobject {
  to_bytes::<GeneralTransactionMetadata>(env, general_transaction_metadata)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<GeneralTransactionMetadata>(env, bytes)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| GeneralTransactionMetadata::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataLen(
  env: JNIEnv, _: JObject, general_transaction_metadata: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let general_transaction_metadata = general_transaction_metadata.rptr(&env)?;
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .map(|general_transaction_metadata| general_transaction_metadata.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataInsert(
  env: JNIEnv, _: JObject, general_transaction_metadata: JRPtr, key: JRPtr, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let general_transaction_metadata = general_transaction_metadata.rptr(&env)?;
    let key = key.rptr(&env)?;
    let value = value.rptr(&env)?;
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .zip(value.typed_ref::<TransactionMetadatum>())
      .map(|((general_transaction_metadata, key), value)| general_transaction_metadata.insert(key, value))
      .and_then(|transaction_metadatum| transaction_metadatum.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataGet(
  env: JNIEnv, _: JObject, general_transaction_metadata: JRPtr, key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let general_transaction_metadata = general_transaction_metadata.rptr(&env)?;
    let key = key.rptr(&env)?;
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .and_then(|(general_transaction_metadata, key)| general_transaction_metadata.get(key).rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_generalTransactionMetadataKeys(
  env: JNIEnv, _: JObject, general_transaction_metadata: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let general_transaction_metadata = general_transaction_metadata.rptr(&env)?;
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .and_then(|general_transaction_metadata| general_transaction_metadata.keys().rptr().jptr(&env))
  })
  .jresult(&env)
}
