use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::metadata::{MetadataList, TransactionMetadatum};


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_metadataListNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| MetadataList::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_metadataListLen(
  env: JNIEnv, _: JObject, metadata_list: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let metadata_list = metadata_list.rptr(&env)?;
    metadata_list
      .typed_ref::<MetadataList>()
      .map(|metadata_list| metadata_list.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_metadataListGet(
  env: JNIEnv, _: JObject, metadata_list: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let metadata_list = metadata_list.rptr(&env)?;
    metadata_list
      .typed_ref::<MetadataList>()
      .map(|metadata_list| metadata_list.get(usize::from_jlong(index)))
      .and_then(|tx_metadatum| tx_metadatum.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_metadataListAdd(
  env: JNIEnv, _: JObject, metadata_list: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let metadata_list = metadata_list.rptr(&env)?;
    let item = item.rptr(&env)?;
    metadata_list
      .typed_ref::<MetadataList>()
      .zip(item.typed_ref::<TransactionMetadatum>())
      .map(|(metadata_list, item)| metadata_list.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
