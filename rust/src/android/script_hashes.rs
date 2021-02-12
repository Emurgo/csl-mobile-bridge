use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::crypto::{ScriptHash};
use cardano_serialization_lib::{ScriptHashes};

impl ToFromBytes for ScriptHashes {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<ScriptHashes, DeserializeError> {
    ScriptHashes::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesToBytes(
  env: JNIEnv, _: JObject, script_hashes: JRPtr
) -> jobject {
  to_bytes::<ScriptHashes>(env, script_hashes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<ScriptHashes>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| ScriptHashes::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesLen(
  env: JNIEnv, _: JObject, script_hashes: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let script_hashes = script_hashes.rptr(&env)?;
    script_hashes
      .typed_ref::<ScriptHashes>()
      .map(|script_hashes| script_hashes.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesGet(
  env: JNIEnv, _: JObject, script_hashes: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let script_hashes = script_hashes.rptr(&env)?;
    script_hashes
      .typed_ref::<ScriptHashes>()
      .map(|script_hashes| script_hashes.get(usize::from_jlong(index)))
      .and_then(|script_hash| script_hash.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashesAdd(
  env: JNIEnv, _: JObject, script_hashes: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let script_hashes = script_hashes.rptr(&env)?;
    let item = item.rptr(&env)?;
    script_hashes
      .typed_ref::<ScriptHashes>()
      .zip(item.typed_ref::<ScriptHash>())
      .map(|(script_hashes, item)| script_hashes.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
