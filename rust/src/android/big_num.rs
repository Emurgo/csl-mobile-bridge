use jni::objects::{JObject, JString};
use jni::sys::{jobject};
use jni::JNIEnv;
use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;

use cardano_serialization_lib::utils::{BigNum};

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bigNumFromStr(
  env: JNIEnv, _: JObject, string: JString
) -> jobject {
  handle_exception_result(|| {
    let rstr = string.string(&env)?;
    let val = BigNum::from_str(&rstr).into_result()?;
    val.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bigNumToStr(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let val = rptr.typed_ref::<BigNum>()?;
    val.to_str().jstring(&env)
  })
  .jresult(&env)
}

// #[allow(non_snake_case)]
// #[no_mangle]
// pub extern "C" fn Java_io_emurgo_chainlibs_Native_valueFromU64(
//   env: JNIEnv, _: JObject, long: jlong
// ) -> jobject {
//   handle_exception_result(|| {
//     let r_u64 = u64::from_jlong(long);
//     Value::from(r_u64).rptr().jptr(&env)
//   })
//   .jresult(&env)
// }

// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_chainlibs_Native_valueCheckedAdd(
//   env: JNIEnv, _: JObject, ptr: JRPtr, other: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let rptr = ptr.rptr(&env)?;
//     let val = rptr.typed_ref::<Value>()?;
//     let rother = other.rptr(&env)?;
//     let otherval = rother.typed_ref::<Value>()?;
//     let res = val.checked_add(otherval).into_result()?;
//     res.rptr().jptr(&env)
//   })
//   .jresult(&env)
// }

// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_chainlibs_Native_valueCheckedSub(
//   env: JNIEnv, _: JObject, ptr: JObject, other: JObject
// ) -> jobject {
//   handle_exception_result(|| {
//     let rptr = ptr.rptr(&env)?;
//     let val = rptr.typed_ref::<Value>()?;
//     let rother = other.rptr(&env)?;
//     let otherval = rother.typed_ref::<Value>()?;
//     let res = val.checked_sub(otherval).into_result()?;
//     res.rptr().jptr(&env)
//   })
//   .jresult(&env)
// }
