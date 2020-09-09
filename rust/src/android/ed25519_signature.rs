use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Ed25519Signature};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_ed25519SignatureToBytes(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let ptr = ptr.rptr(&env)?;
    ptr
      .typed_ref::<Ed25519Signature>()
      .map(|signature| signature.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_ed25519SignatureFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| Ed25519Signature::from_bytes(bytes).into_result())
      .and_then(|signature: Ed25519Signature| signature.rptr().jptr(&env))
  })
  .jresult(&env)
}
