use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jint, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Ed25519KeyHash, ScriptHash};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};

impl ToFromBytes for StakeCredential {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeCredential, DeserializeError> {
    StakeCredential::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialFromKeyHash(
  env: JNIEnv, _: JObject, key_hash_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let key_hash = key_hash_ptr.rptr(&env)?;
    key_hash
      .typed_ref::<Ed25519KeyHash>()
      .map(|key_hash| StakeCredential::from_keyhash(key_hash))
      .and_then(|stake_credential| stake_credential.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialFromScriptHash(
  env: JNIEnv, _: JObject, script_hash_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let script_hash = script_hash_ptr.rptr(&env)?;
    script_hash
      .typed_ref::<ScriptHash>()
      .map(|script_hash| StakeCredential::from_scripthash(script_hash))
      .and_then(|stake_credential| stake_credential.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialToKeyHash(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<StakeCredential>().and_then(|stake_credential| stake_credential.to_keyhash().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialToScriptHash(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<StakeCredential>().and_then(|stake_credential| stake_credential.to_scripthash().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialKind(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<StakeCredential>()
      .map(|credential| credential.kind())
      .and_then(|kind| (kind as jint).jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialToBytes(
  env: JNIEnv, _: JObject, stake_credential: JRPtr
) -> jobject {
  to_bytes::<StakeCredential>(env, stake_credential)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeCredentialFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<StakeCredential>(env, bytes)
}
