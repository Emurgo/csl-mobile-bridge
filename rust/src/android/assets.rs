use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject};
use jni::JNIEnv;
use cardano_serialization_lib::{Assets, AssetName};
use cardano_serialization_lib::utils::{BigNum};


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetsNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| Assets::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetsLen(
  env: JNIEnv, _: JObject, assets: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let assets = assets.rptr(&env)?;
    assets
      .typed_ref::<Assets>()
      .map(|assets| assets.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetsInsert(
  env: JNIEnv, _: JObject, assets: JRPtr, key: JRPtr, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let assets = assets.rptr(&env)?;
    let key = key.rptr(&env)?;
    let value = value.rptr(&env)?;
    assets
      .typed_ref::<Assets>()
      .zip(key.typed_ref::<AssetName>())
      .zip(value.typed_ref::<BigNum>())
      .map(|((assets, key), value)| assets.insert(key, *value))
      .and_then(|coin| coin.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetsGet(
  env: JNIEnv, _: JObject, assets: JRPtr, key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let assets = assets.rptr(&env)?;
    let key = key.rptr(&env)?;
    assets
      .typed_ref::<Assets>()
      .zip(key.typed_ref::<AssetName>())
      .and_then(|(assets, key)| assets.get(key).rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetsKeys(
  env: JNIEnv, _: JObject, assets: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let assets = assets.rptr(&env)?;
    assets
      .typed_ref::<Assets>()
      .and_then(|assets| assets.keys().rptr().jptr(&env))
  })
  .jresult(&env)
}
