use super::ptr_j::*;
// use crate::panic::{handle_exception_result, ToResult};
// use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{ScriptHash};
use cardano_serialization_lib::error::{DeserializeError};

impl ToFromBytes for ScriptHash {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<ScriptHash, DeserializeError> {
    ScriptHash::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashToBytes(
  env: JNIEnv, _: JObject, script_hash: JRPtr
) -> jobject {
  to_bytes::<ScriptHash>(env, script_hash)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_scriptHashFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<ScriptHash>(env, bytes)
}
