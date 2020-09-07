use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::ToJniString;
use super::string::ToString;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jlong, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::Bip32PublicKey;
use std::convert::TryFrom;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyDerive(
  env: JNIEnv, _: JObject, bip32_public_key: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let bip32_public_key = bip32_public_key.rptr(&env)?;
    let idx_u32 = u32::try_from(index).map_err(|err| err.to_string())?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .and_then(|bip32_public_key| bip32_public_key.derive(idx_u32).into_result())
      .and_then(|bip32_public_key| bip32_public_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyToRawKey(
  env: JNIEnv, _: JObject, bip32_public_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip32_public_key = bip32_public_key.rptr(&env)?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.to_raw_key())
      .and_then(|public_key| public_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| Bip32PublicKey::from_bytes(&bytes).into_result())
      .and_then(|bip32_public_key| bip32_public_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyAsBytes(
  env: JNIEnv, _: JObject, bip32_public_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip32_public_key = bip32_public_key.rptr(&env)?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.as_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyFromBech32(
  env: JNIEnv, _: JObject, bech32_str: JString
) -> jobject {
  handle_exception_result(|| {
    bech32_str
      .string(&env)
      .and_then(|bech32_str| Bip32PublicKey::from_bech32(&bech32_str).into_result())
      .and_then(|bip32_public_key| bip32_public_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyToBech32(
  env: JNIEnv, _: JObject, bip32_public_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip32_public_key = bip32_public_key.rptr(&env)?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .and_then(|bip32_public_key| bip32_public_key.to_bech32().jstring(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PublicKeyChaincode(
  env: JNIEnv, _: JObject, bip32_public_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip32_public_key = bip32_public_key.rptr(&env)?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.chaincode())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}
