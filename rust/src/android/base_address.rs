use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
// use super::string::ToJniString;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cddl_lib::address::{BaseAddress, StakeCredential};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressNew(
  env: JNIEnv, _: JObject, network: jint, payment: JRPtr, stake: JRPtr
) -> jobject {
  let payment = payment.owned::<StakeCredential>(&env);
  let stake = stake.owned::<StakeCredential>(&env);
  handle_exception_result(|| {
    BaseAddress::new(network as u8, payment?, stake?).rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressPaymentCred(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<BaseAddress>().and_then(|base_address| base_address.payment_cred().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressStakeCred(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<BaseAddress>().and_then(|base_address| base_address.stake_cred().rptr().jptr(&env))
  })
  .jresult(&env)
}
