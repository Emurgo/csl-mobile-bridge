use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::ToJniString;
use super::string::ToString;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jlong, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{Bip32PrivateKey};
use std::convert::TryFrom;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyDerive(
  env: JNIEnv, _: JObject, bip_32_private_key: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let bip_32_private_key = bip_32_private_key.rptr(&env)?;
    let idx_u32 = u32::try_from(index).map_err(|err| err.to_string())?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.derive(idx_u32))
      .and_then(|bip_32_private_key| bip_32_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyGenerateEd25519Bip32(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| {
    Bip32PrivateKey::generate_ed25519_bip32()
      .into_result()
      .and_then(|bip_32_private_key| bip_32_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyToRawKey(
  env: JNIEnv, _: JObject, bip_32_private_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip_32_private_key = bip_32_private_key.rptr(&env)?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.to_raw_key())
      .and_then(|raw_private_key| raw_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyToPublic(
  env: JNIEnv, _: JObject, bip_32_private_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip_32_private_key = bip_32_private_key.rptr(&env)?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.to_public())
      .and_then(|bip_32_public_key| bip_32_public_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| Bip32PrivateKey::from_bytes(&bytes).into_result())
      .and_then(|bip_32_private_key| bip_32_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyAsBytes(
  env: JNIEnv, _: JObject, bip_32_private_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip_32_private_key = bip_32_private_key.rptr(&env)?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.as_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyFromBech32(
  env: JNIEnv, _: JObject, bech32_str: JString
) -> jobject {
  handle_exception_result(|| {
    bech32_str
      .string(&env)
      .and_then(|bech32_str| Bip32PrivateKey::from_bech32(&bech32_str).into_result())
      .and_then(|bip_32_private_key| bip_32_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyToBech32(
  env: JNIEnv, _: JObject, bip_32_private_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let bip_32_private_key = bip_32_private_key.rptr(&env)?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .and_then(|bip_32_private_key| bip_32_private_key.to_bech32().jstring(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_bip32PrivateKeyFromBip39Entropy(
  env: JNIEnv, _: JObject, entropy: jbyteArray, password: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(entropy)
      .into_result()
      .zip(env.convert_byte_array(password).into_result())
      .map(|(entropy, password)| Bip32PrivateKey::from_bip39_entropy(&entropy, &password))
      .and_then(|bip_32_private_key| bip_32_private_key.rptr().jptr(&env))
  })
  .jresult(&env)
}
