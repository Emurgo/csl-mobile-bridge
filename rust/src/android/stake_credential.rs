use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Ed25519KeyHash};
use cardano_serialization_lib::address::{StakeCredential};

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
