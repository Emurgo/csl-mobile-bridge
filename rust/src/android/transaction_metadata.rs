// use super::primitive::ToPrimitiveObject;
// use super::ptr_j::*;
// use super::result::ToJniResult;
// use crate::panic::{handle_exception_result, Zip};
// use crate::ptr::RPtrRepresentable;
// use crate::utils::ToFromBytes;
// use super::utils::{to_bytes, from_bytes};
// use jni::objects::JObject;
// use jni::sys::{jobject, jbyteArray, jlong};
// use jni::JNIEnv;
// use cardano_serialization_lib::error::{DeserializeError};
// use cardano_serialization_lib::metadata::{TransactionMetadata, TransactionMetadatum, TransactionMetadatumLabels};
// use cardano_serialization_lib::utils::{BigNum};
//
// pub type TransactionMetadatumLabel = BigNum;
//
// impl ToFromBytes for TransactionMetadata {
//   fn to_bytes(&self) -> Vec<u8> {
//     self.to_bytes()
//   }
//
//   fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadata, DeserializeError> {
//     TransactionMetadata::from_bytes(bytes)
//   }
// }
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataToBytes(
//   env: JNIEnv, _: JObject, transaction_metadata: JRPtr
// ) -> jobject {
//   to_bytes::<TransactionMetadata>(env, transaction_metadata)
// }
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataFromBytes(
//   env: JNIEnv, _: JObject, bytes: jbyteArray
// ) -> jobject {
//   from_bytes::<TransactionMetadata>(env, bytes)
// }
//
//
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadataNew(
//   env: JNIEnv, _: JObject
// ) -> jobject {
//   handle_exception_result(|| TransactionMetadata::new().rptr().jptr(&env)).jresult(&env)
// }
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
