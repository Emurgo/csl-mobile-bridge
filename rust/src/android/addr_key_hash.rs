use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::ToJniString;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject};
use jni::sys::{jbyteArray, jobject};
use jni::JNIEnv;
use cddl_lib::crypto::{AddrKeyHash};

// cddl_lib: (&self) -> Vec<u8>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addrKeyHashToBytes(
  env: JNIEnv, _: JObject, addr_key_hash: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let addr_key_hash = addr_key_hash.rptr(&env)?;
    addr_key_hash
      .typed_ref::<AddrKeyHash>()
      .map(|addr_key_hash| addr_key_hash.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

// cddl_lib: from_bytes(Vec<u8>) -> Result<Address, JsValue>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addrKeyHashFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| AddrKeyHash::from_bytes(bytes).into_result())
      .and_then(|addr_key_hash| addr_key_hash.rptr().jptr(&env))
  })
  .jresult(&env)
}
