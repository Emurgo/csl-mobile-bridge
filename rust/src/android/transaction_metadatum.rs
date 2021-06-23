use super::ptr_j::*;
use super::utils::{to_bytes, from_bytes};
use crate::utils::ToFromBytes;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use super::result::ToJniResult;
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{TransactionMetadatum, MetadataList};

impl ToFromBytes for TransactionMetadatum {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadatum, DeserializeError> {
    TransactionMetadatum::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumToBytes(
  env: JNIEnv, _: JObject, transaction_metadatum: JRPtr
) -> jobject {
  to_bytes::<TransactionMetadatum>(env, transaction_metadatum)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<TransactionMetadatum>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionMetadatumNewList(
  env: JNIEnv, _: JObject, metadata_list_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let metadata_list = metadata_list_ptr.rptr(&env)?;
    metadata_list
      .typed_ref::<MetadataList>()
      .map(|metadata_list| TransactionMetadatum::new_list(metadata_list))
      .and_then(|transaction_metadatum| transaction_metadatum.rptr().jptr(&env))
  })
  .jresult(&env)
}
