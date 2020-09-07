use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::address::{Address, RewardAddress, StakeCredential};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressNew(
  env: JNIEnv, _: JObject, network: jint, payment: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let payment = payment.rptr(&env)?;
    payment
    .typed_ref::<StakeCredential>()
    .map(|payment| RewardAddress::new(network as u8, payment))
    .and_then(|reward_address| reward_address.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressPaymentCred(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<RewardAddress>().and_then(|reward_address| reward_address.payment_cred().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressToAddress(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<RewardAddress>().and_then(|reward_address| reward_address.to_address().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressFromAddress(
  env: JNIEnv, _: JObject, address: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let address = address.rptr(&env)?;
    address
      .typed_ref::<Address>()
      .map(|address| RewardAddress::from_address(address))
      .and_then(|reward_address| reward_address.rptr().jptr(&env))
  })
  .jresult(&env)
}
