use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::utils::{BigNum};
use cardano_serialization_lib::metadata::{
  GeneralTransactionMetadata,
  AuxiliaryData,
};

pub type TransactionMetadatumLabel = BigNum;

impl ToFromBytes for AuxiliaryData {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<AuxiliaryData, DeserializeError> {
    AuxiliaryData::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataToBytes(
  env: JNIEnv, _: JObject, transaction_metadata: JRPtr
) -> jobject {
  to_bytes::<TransactionMetadata>(env, transaction_metadata)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<TransactionMetadata>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_txAuxiliaryDataNew(
  env: JNIEnv, _: JObject, metadata_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let metadata = metadata_ptr.rptr(&env)?;
    metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .map(|metadata| { 
        let tx_aux_data = AuxiliaryData::new();
        tx_aux_data::set_metadata(&metadata);
        tx_aux_data 
      })
      .and_then(|tx_aux_data| tx_aux_data.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_txAuxiliaryDataMetadata(
  env: JNIEnv, _: JObject, tx_aux_data_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_aux_data = tx_aux_data_ptr.rptr(&env)?;
    tx_aux_data
      .typed_ref::<AuxiliaryData>()
      .map(|tx_aux_data| tx_aux_data.metadata())
      .and_then(|metadata| metadata.rptr().jptr(&env))
  })
  .jresult(&env)
}
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataLen(
//   env: JNIEnv, _: JObject, transaction_metadata: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let transaction_metadata = transaction_metadata.rptr(&env)?;
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .map(|transaction_metadata| transaction_metadata.len())
//       .and_then(|len| len.into_jlong().jobject(&env))
//   })
//   .jresult(&env)
// }
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataInsert(
//   env: JNIEnv, _: JObject, transaction_metadata: JRPtr, key: JRPtr, value: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let transaction_metadata = transaction_metadata.rptr(&env)?;
//     let key = key.rptr(&env)?;
//     let value = value.rptr(&env)?;
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .zip(key.typed_ref::<TransactionMetadatumLabel>())
//       .zip(value.typed_ref::<TransactionMetadatum>())
//       .map(|((transaction_metadata, key), value)| transaction_metadata.insert(key, value))
//       .and_then(|transaction_metadatum| transaction_metadatum.rptr().jptr(&env))
//   })
//   .jresult(&env)
// }
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataGet(
//   env: JNIEnv, _: JObject, transaction_metadata: JRPtr, key: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let transaction_metadata = transaction_metadata.rptr(&env)?;
//     let key = key.rptr(&env)?;
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .zip(key.typed_ref::<TransactionMetadatumLabel>())
//       .and_then(|(transaction_metadata, key)| transaction_metadata.get(key).rptr().jptr(&env))
//   })
//   .jresult(&env)
// }
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataKeys(
//   env: JNIEnv, _: JObject, transaction_metadata: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let transaction_metadata = transaction_metadata.rptr(&env)?;
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .and_then(|transaction_metadata| transaction_metadata.keys().rptr().jptr(&env))
//   })
//   .jresult(&env)
// }
