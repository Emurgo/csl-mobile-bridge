use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::{StakeRegistration};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};

impl ToFromBytes for StakeRegistration {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeRegistration, DeserializeError> {
    StakeRegistration::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeRegistrationToBytes(
  env: JNIEnv, _: JObject, stake_registration: JRPtr
) -> jobject {
  to_bytes::<StakeRegistration>(env, stake_registration)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeRegistrationFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<StakeRegistration>(env, bytes)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeRegistrationStakeCredential(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<StakeRegistration>().and_then(|stake_registration| stake_registration.stake_credential().rptr().jptr(&env))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_stakeRegistrationNew(
  env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let stake_credential = stake_credential_ptr.rptr(&env)?;
    stake_credential
      .typed_ref::<StakeCredential>()
      .map(|stake_credential| StakeRegistration::new(stake_credential))
      .and_then(|stake_registration| stake_registration.rptr().jptr(&env))
  })
  .jresult(&env)
}
