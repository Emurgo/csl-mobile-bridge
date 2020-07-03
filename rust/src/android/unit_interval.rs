use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cddl_lib::{UnitInterval};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_unitIntervalToBytes(
  env: JNIEnv, _: JObject, unit_interval: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let unit_interval = unit_interval.rptr(&env)?;
    unit_interval
      .typed_ref::<UnitInterval>()
      .map(|unit_interval| unit_interval.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_unitIntervalFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| UnitInterval::from_bytes(bytes).into_result())
      .and_then(|unit_interval| unit_interval.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_unitIntervalNew(
  env: JNIEnv, _: JObject, index_0: jint, index_1: jint
) -> jobject {
  handle_exception_result(|| {
    UnitInterval::new(index_0 as u32, index_1 as u32).rptr().jptr(&env)
  })
  .jresult(&env)
}
