use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject};
use jni::JNIEnv;
use cardano_serialization_lib::address::RewardAddress;
use cardano_serialization_lib::Withdrawals;
use cardano_serialization_lib::utils::{Coin};


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_withdrawalsNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| Withdrawals::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_withdrawalsLen(
  env: JNIEnv, _: JObject, withdrawals: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let withdrawals = withdrawals.rptr(&env)?;
    withdrawals
      .typed_ref::<Withdrawals>()
      .map(|withdrawals| withdrawals.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_withdrawalsInsert(
  env: JNIEnv, _: JObject, withdrawals: JRPtr, key: JRPtr, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let withdrawals = withdrawals.rptr(&env)?;
    let key = key.rptr(&env)?;
    let value = value.rptr(&env)?;
    withdrawals
      .typed_ref::<Withdrawals>()
      .zip(key.typed_ref::<RewardAddress>())
      .zip(value.typed_ref::<Coin>())
      .map(|((withdrawals, key), value)| withdrawals.insert(key, value))
      .and_then(|coin| coin.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_withdrawalsGet(
  env: JNIEnv, _: JObject, withdrawals: JRPtr, key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let withdrawals = withdrawals.rptr(&env)?;
    let key = key.rptr(&env)?;
    withdrawals
      .typed_ref::<Withdrawals>()
      .zip(key.typed_ref::<RewardAddress>())
      .and_then(|(withdrawals, key)| withdrawals.get(key).rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_withdrawalsKeys(
  env: JNIEnv, _: JObject, withdrawals: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let withdrawals = withdrawals.rptr(&env)?;
    withdrawals
      .typed_ref::<Withdrawals>()
      .and_then(|withdrawals| withdrawals.keys().rptr().jptr(&env))
  })
  .jresult(&env)
}
