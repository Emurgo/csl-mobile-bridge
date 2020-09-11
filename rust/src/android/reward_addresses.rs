use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::address::RewardAddress;


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressesNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| RewardAddresses::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressesLen(
  env: JNIEnv, _: JObject, reward_addresses: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let reward_addresses = reward_addresses.rptr(&env)?;
    reward_addresses
      .typed_ref::<RewardAddresses>()
      .map(|reward_addresses| reward_addresses.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressesGet(
  env: JNIEnv, _: JObject, reward_addresses: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let reward_addresses = reward_addresses.rptr(&env)?;
    reward_addresses
      .typed_ref::<RewardAddresses>()
      .map(|reward_addresses| reward_addresses.get(usize::from_jlong(index)))
      .and_then(|reward_address| reward_address.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_rewardAddressesAdd(
  env: JNIEnv, _: JObject, reward_addresses: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let reward_addresses = reward_addresses.rptr(&env)?;
    let item = item.rptr(&env)?;
    reward_addresses
      .typed_ref::<RewardAddresses>()
      .zip(item.typed_ref::<RewardAddress>())
      .map(|(reward_addresses, item)| reward_addresses.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
