use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Ed25519KeyHash};

// cddl_lib: (&self) -> Vec<u8>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_ed25519KeyHashToBytes(
  env: JNIEnv, _: JObject, ed25519_key_hash: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let ed25519_key_hash = ed25519_key_hash.rptr(&env)?;
    ed25519_key_hash
      .typed_ref::<Ed25519KeyHash>()
      .map(|ed25519_key_hash| ed25519_key_hash.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

// cddl_lib: from_bytes(Vec<u8>) -> Result<Address, JsValue>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_ed25519KeyHashFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| Ed25519KeyHash::from_bytes(bytes).into_result())
      .and_then(|ed25519_key_hash| ed25519_key_hash.rptr().jptr(&env))
  })
  .jresult(&env)
}
