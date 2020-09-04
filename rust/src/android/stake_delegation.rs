use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::{StakeDelegation};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::crypto::{Ed25519KeyHash};

impl ToFromBytes for StakeDelegation {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeDelegation, DeserializeError> {
    StakeDelegation::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeDelegationToBytes(
  env: JNIEnv, _: JObject, stake_delegation: JRPtr
) -> jobject {
  to_bytes::<StakeDelegation>(env, stake_delegation)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeDelegationFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<StakeDelegation>(env, bytes)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeDelegationStakeCredential(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<StakeDelegation>().and_then(|stake_delegation| stake_delegation.stake_credential().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeDelegationPoolKeyhash(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<StakeDelegation>().and_then(|stake_delegation| stake_delegation.pool_keyhash().rptr().jptr(&env))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeDelegationNew(
  env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let stake_credential = stake_credential_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_ptr.rptr(&env)?;
    stake_credential
      .typed_ref::<StakeCredential>()
      .zip(pool_keyhash.typed_ref::<Ed25519KeyHash>())
      .and_then(
        |(stake_credential, pool_keyhash)| {
          StakeDelegation::new(stake_credential, pool_keyhash).rptr().jptr(&env)
        }
      )
  })
  .jresult(&env)
}
