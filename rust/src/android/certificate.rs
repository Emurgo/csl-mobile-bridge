use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;
use cardano_serialization_lib::{StakeRegistration, Certificate};
use cardano_serialization_lib::error::{DeserializeError};

impl ToFromBytes for Certificate {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Certificate, DeserializeError> {
    Certificate::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificateToBytes(
  env: JNIEnv, _: JObject, certificate: JRPtr
) -> jobject {
  to_bytes::<Certificate>(env, certificate)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificateFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<Certificate>(env, bytes)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificateNewStakeRegistration(
  env: JNIEnv, _: JObject, stake_reg_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let stake_reg = stake_reg_ptr.rptr(&env)?;
    stake_reg
      .typed_ref::<StakeRegistration>()
      .map(|stake_reg| Certificate::new_stake_registration(stake_reg))
      .and_then(|certificate| certificate.rptr().jptr(&env))
  })
  .jresult(&env)
}
