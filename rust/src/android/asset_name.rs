/**
 * AssetName
 */

use jni::objects::{JObject};
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{AssetName};

impl ToFromBytes for AssetName {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<AssetName, DeserializeError> {
    AssetName::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNameToBytes(
  env: JNIEnv, _: JObject, asset_name: JRPtr
) -> jobject {
  to_bytes::<AssetName>(env, asset_name)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNameFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<AssetName>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNameNew(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| AssetName::new(bytes).into_result())
      .and_then(|asset_name| asset_name.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_assetNameName(
  env: JNIEnv, _: JObject, asset_name: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let obj = asset_name.rptr(&env)?;
    obj
      .typed_ref::<AssetName>()
      .map(|obj| obj.name())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}
