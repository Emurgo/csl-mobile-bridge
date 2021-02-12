use jni::objects::{JObject};
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::utils::{Value, Coin};
use cardano_serialization_lib::{MultiAsset};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueNew(
  env: JNIEnv, _: JObject, coin_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let coin = coin_ptr.rptr(&env)?;
    coin
      .typed_ref::<Coin>()
      .map(|coin| Value::new(coin))
      .and_then(|val| val.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueCoin(
  env: JNIEnv, _: JObject, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let value = value.rptr(&env)?;
    value
      .typed_ref::<Value>()
      .map(|value| value.coin())
      .and_then(|coin| coin.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueSetCoin(
  env: JNIEnv, _: JObject, value: JRPtr, coin: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let value = value.rptr(&env)?;
    let coin = coin.rptr(&env)?;
    value
      .typed_ref::<Value>()
      .zip(coin.typed_ref::<Coin>())
      .map(|(value, coin)| value.set_coin(coin))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueMultiasset(
  env: JNIEnv, _: JObject, value: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let value = value.rptr(&env)?;
    value
      .typed_ref::<Value>()
      .map(|value| value.multiasset())
      .and_then(|multiasset| multiasset.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueSetMultiasset(
  env: JNIEnv, _: JObject, value: JRPtr, multiasset: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let value = value.rptr(&env)?;
    let multiasset = multiasset.rptr(&env)?;
    value
      .typed_ref::<Value>()
      .zip(multiasset.typed_ref::<MultiAsset>())
      .map(|(value, multiasset)| value.set_multiasset(multiasset))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueCheckedAdd(
  env: JNIEnv, _: JObject, ptr: JRPtr, rhs: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let ptr = ptr.rptr(&env)?;
    let val = ptr.typed_ref::<Value>()?;
    let rhs = rhs.rptr(&env)?;
    let rhs_val = rhs.typed_ref::<Value>()?;
    let res = val.checked_add(rhs_val).into_result()?;
    res.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueCheckedSub(
  env: JNIEnv, _: JObject, ptr: JRPtr, rhs: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let ptr = ptr.rptr(&env)?;
    let val = ptr.typed_ref::<Value>()?;
    let rhs = rhs.rptr(&env)?;
    let rhs_val = rhs.typed_ref::<Value>()?;
    let res = val.checked_sub(rhs_val).into_result()?;
    res.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueClampedSub(
  env: JNIEnv, _: JObject, ptr: JRPtr, rhs: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let ptr = ptr.rptr(&env)?;
    let val = ptr.typed_ref::<Value>()?;
    let rhs = rhs.rptr(&env)?;
    let rhs_val = rhs.typed_ref::<Value>()?;
    let res = val.clamped_sub(rhs_val);
    res.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_valueCompare(
  env: JNIEnv, _: JObject, value_ptr: JRPtr, rhs_value_ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let value_ptr = value_ptr.rptr(&env)?;
    let rhs_value_ptr = rhs_value_ptr.rptr(&env)?;
    value_ptr
      .typed_ref::<Value>()
      .zip(rhs_value_ptr.typed_ref::<Value>())
      .map(|(value, rhs_value)| value.compare(rhs_value).map(|res| (res as jint))) // Result<Option<i8>>
      .and_then(|res| {
        match res {
          Some(res) => res.jobject(&env),
          None => Ok(JObject::null())
        }
      })
  })
  .jresult(&env)
}
