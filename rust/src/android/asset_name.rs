use jni::objects::{JObject};
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;

use cardano_serialization_lib::{AssetName};

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
