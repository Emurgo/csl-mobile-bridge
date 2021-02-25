use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject};
use jni::JNIEnv;
use cardano_serialization_lib::{Assets, PolicyID, MultiAsset};


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| MultiAsset::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetLen(
  env: JNIEnv, _: JObject, multiAsset: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let multiAsset = multiAsset.rptr(&env)?;
    multiAsset
      .typed_ref::<MultiAsset>()
      .map(|multiAsset| multiAsset.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetInsert(
  env: JNIEnv, _: JObject, multiAsset: JRPtr, key: JRPtr, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let multiAsset = multiAsset.rptr(&env)?;
    let key = key.rptr(&env)?;
    let value = value.rptr(&env)?;
    multiAsset
      .typed_ref::<MultiAsset>()
      .zip(key.typed_ref::<PolicyID>())
      .zip(value.typed_ref::<Assets>())
      .map(|((multiAsset, key), value)| multiAsset.insert(key, value))
      .and_then(|coin| coin.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetGet(
  env: JNIEnv, _: JObject, multiAsset: JRPtr, key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let multiAsset = multiAsset.rptr(&env)?;
    let key = key.rptr(&env)?;
    multiAsset
      .typed_ref::<MultiAsset>()
      .zip(key.typed_ref::<PolicyID>())
      .and_then(|(multiAsset, key)| multiAsset.get(key).rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetKeys(
  env: JNIEnv, _: JObject, multiAsset: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let multiAsset = multiAsset.rptr(&env)?;
    multiAsset
      .typed_ref::<MultiAsset>()
      .and_then(|multiAsset| multiAsset.keys().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_multiAssetSub(
  env: JNIEnv, _: JObject, ptr: JObject, other: JObject
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let rptr_other = other.rptr(&env)?;
    rptr
      .typed_ref::<MultiAsset>()
      .zip(rptr_other.typed_ref::<MultiAsset>())
      .map(|(val, other)| val.sub(other))
      .and_then(|res| {
        res.rptr().jptr(&env)
      })
  })
  .jresult(&env)
}
