use std::convert::TryFrom;
use jni::objects::{JObject, JString};
use jni::sys::{jobject, jboolean, jlong};
use jni::JNIEnv;
use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use super::primitive::ToPrimitiveObject;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::address::{Address, ByronAddress};
use cardano_serialization_lib::crypto::Bip32PublicKey;

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

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressIsValid(
  env: JNIEnv, _: JObject, string: JString
) -> jobject {
  handle_exception_result(|| {
    let rstr = string.string(&env)?;
    let val = ByronAddress::is_valid(&rstr);
    (val as jboolean).jobject(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressToAddress(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<ByronAddress>()
      .and_then(|byron_addr| byron_addr.to_address().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressFromAddress(
  env: JNIEnv, _: JObject, address: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let address = address.rptr(&env)?;
    address
      .typed_ref::<Address>()
      .map(|address| ByronAddress::from_address(address))
      .and_then(|byron_address| byron_address.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressByronProtocolMagic(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<ByronAddress>()
      .map(|addr| addr.byron_protocol_magic())
      .and_then(|protocol_magic| (protocol_magic as jlong).jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressAttributes(
  env: JNIEnv, _: JObject, byron_address: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let byron_address = byron_address.rptr(&env)?;
    byron_address
      .typed_ref::<ByronAddress>()
      .map(|byron_address| byron_address.attributes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_byronAddressIcarusFromKey(
  env: JNIEnv, _: JObject, key: JRPtr, protocol_magic: jlong
) -> jobject {
  handle_exception_result(|| {
    let key = key.rptr(&env)?;
    let magic_u32 = u32::try_from(protocol_magic).map_err(|err| err.to_string())?;
    key
      .typed_ref::<Bip32PublicKey>()
      .map(|key| ByronAddress::icarus_from_key(key, magic_u32))
      .and_then(|byron_address| byron_address.rptr().jptr(&env))
  })
  .jresult(&env)
}
