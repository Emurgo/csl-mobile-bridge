use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::address::{Address, BaseAddress, StakeCredential};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressNew(
  env: JNIEnv, _: JObject, network: jint, payment: JRPtr, stake: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let payment = payment.rptr(&env)?;
    let stake = stake.rptr(&env)?;
    payment.typed_ref::<StakeCredential>().zip(stake.typed_ref::<StakeCredential>()).and_then(
      |(payment, stake)| {
        BaseAddress::new(network as u8, payment, stake).rptr().jptr(&env)
      }
    )
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

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressToAddress(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<BaseAddress>().and_then(|base_address| base_address.to_address().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_baseAddressFromAddress(
  env: JNIEnv, _: JObject, address: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let address = address.rptr(&env)?;
    address
      .typed_ref::<Address>()
      .map(|address| BaseAddress::from_address(address))
      .and_then(|base_address| base_address.rptr().jptr(&env))
  })
  .jresult(&env)
}
