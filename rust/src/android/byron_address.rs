use jni::objects::{JObject, JString};
use jni::sys::{jobject};
use jni::JNIEnv;
use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::address::{ByronAddress};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressToBase58(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let val = rptr.typed_ref::<ByronAddress>()?;
    val.to_base58().jstring(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressFromBase58(
  env: JNIEnv, _: JObject, string: JString
) -> jobject {
  handle_exception_result(|| {
    let rstr = string.string(&env)?;
    let val = ByronAddress::from_base58(&rstr).into_result()?;
    val.rptr().jptr(&env)
  })
  .jresult(&env)
}
