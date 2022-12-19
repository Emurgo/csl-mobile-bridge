use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jobject, jint};
use jni::JNIEnv;
use crate::utils::ToFromBytes;

// to/from bytes

pub unsafe fn to_bytes<T: RPtrRepresentable + ToFromBytes>(
  env: JNIEnv, obj: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let obj = obj.rptr(&env)?;
    obj
      .typed_ref::<T>()
      .map(|obj| obj.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from_raw(arr))
  })
  .jresult(&env)
}

pub unsafe fn from_bytes<T: RPtrRepresentable + ToFromBytes>(
  env: JNIEnv, bytes: jbyteArray,
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| T::from_bytes(bytes).into_result())
      .and_then(|obj| obj.rptr().jptr(&env))
  })
  .jresult(&env)
}