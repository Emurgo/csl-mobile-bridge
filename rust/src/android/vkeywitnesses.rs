use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Vkeywitness, Vkeywitnesses};


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_vkeywitnessesNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| Vkeywitnesses::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_vkeywitnessesLen(
  env: JNIEnv, _: JObject, witnesses: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let witnesses = witnesses.rptr(&env)?;
    witnesses
      .typed_ref::<Vkeywitnesses>()
      .map(|witnesses| witnesses.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_vkeywitnessesAdd(
  env: JNIEnv, _: JObject, vkeywitnesses: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let vkeywitnesses = vkeywitnesses.rptr(&env)?;
    let item = item.rptr(&env)?;
    vkeywitnesses
      .typed_ref::<Vkeywitnesses>()
      .zip(item.typed_ref::<Vkeywitness>())
      .map(|(vkeywitnesses, item)| vkeywitnesses.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
