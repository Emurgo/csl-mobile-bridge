use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jobject, jint};
use jni::JNIEnv;
use super::primitive::ToPrimitiveObject;
use cardano_serialization_lib::address::{Address};

// cddl_lib: (&self) -> Vec<u8>
// from react-native-chain-libs address.as_bytes (&self) -> Vec<u8>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressToBytes(
  env: JNIEnv, _: JObject, address: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let address = address.rptr(&env)?;
    address
      .typed_ref::<Address>()
      .map(|address| address.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

// cddl_lib: Address.from_bytes(Vec<u8>) -> Result<Address, JsValue>
// from react-native-chain-libs address.from_bytes(&[u8]) -> Result<Address, JsValue>
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| Address::from_bytes(bytes).into_result())
      .and_then(|address: Address| address.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressToBech32(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let val = rptr.typed_ref::<Address>()?;
    val.to_bech32(None).into_result()
    .and_then(|address_str| address_str.jstring(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressToBech32WithPrefix(
  env: JNIEnv, _: JObject, ptr: JRPtr, prefix: JString
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let rstr = prefix.string(&env)?;
    let val = rptr.typed_ref::<Address>()?;
    val.to_bech32(Some(rstr)).into_result()
    .and_then(|address_str| address_str.jstring(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressFromBech32(
  env: JNIEnv, _: JObject, string: JString
) -> jobject {
  handle_exception_result(|| {
    let rstr = string.string(&env)?;
    let val = Address::from_bech32(&rstr).into_result()?;
    val.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_addressNetworkId(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<Address>()
      .and_then(|addr| addr.network_id().into_result())
      .and_then(|network_id| (network_id as jint).jobject(&env))
  })
  .jresult(&env)
}
