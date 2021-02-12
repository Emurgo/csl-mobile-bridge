/**
 * AssetNames
 */

use jni::objects::{JObject};
use jni::sys::{jobject, jlong};
use jni::JNIEnv;
use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;

use cardano_serialization_lib::{AssetName, AssetNames};



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNamesNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| AssetNames::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNamesLen(
  env: JNIEnv, _: JObject, asset_names: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let asset_names = asset_names.rptr(&env)?;
    asset_names
      .typed_ref::<AssetNames>()
      .map(|asset_names| asset_names.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNamesGet(
  env: JNIEnv, _: JObject, asset_names: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let asset_names = asset_names.rptr(&env)?;
    asset_names
      .typed_ref::<AssetNames>()
      .map(|asset_names| asset_names.get(usize::from_jlong(index)))
      .and_then(|asset_name| asset_name.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNamesAdd(
  env: JNIEnv, _: JObject, asset_names: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let asset_names = asset_names.rptr(&env)?;
    let item = item.rptr(&env)?;
    asset_names
      .typed_ref::<AssetNames>()
      .zip(item.typed_ref::<AssetName>())
      .map(|(asset_names, item)| asset_names.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
