use jni::objects::{JObject, JString};
use jni::sys::{jobject, jbyteArray};
use jni::JNIEnv;

use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::RPtrRepresentable;

use crate::cardano_serialization_lib::crypto::PublicKey;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyFromBech32(
  env: JNIEnv, _: JObject, bech32_str: JString
) -> jobject {
  handle_exception_result(|| {
    let rstr = bech32_str.string(&env)?;
    let val = PublicKey::from_bech32(&rstr).into_result()?;
    val.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyToBech32(
  env: JNIEnv, _: JObject, public_key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let public_key = public_key.rptr(&env)?;
    public_key
      .typed_ref::<PublicKey>()
      .and_then(|public_key| public_key.to_bech32().jstring(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| PublicKey::from_bytes(&bytes).into_result())
      .and_then(|pubkey: PublicKey| pubkey.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyAsBytes(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    let pubkey = rptr.typed_ref::<PublicKey>()?;
    env.byte_array_from_slice(&pubkey.as_bytes()).map(|arr| JObject::from(arr)).into_result()
  })
  .jresult(&env)
}

// TODO: cannot implement yet since Ed25519Signature is missing.
// #[allow(non_snake_case)]
// #[no_mangle]
// pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyVerify(
//   env: JNIEnv, _: JObject, ptr: JRPtr, data: jbyteArray, sig_ptr: JRPtr
// ) -> jobject {
//   handle_exception_result(|| {
//     let rptr = ptr.rptr(&env)?;
//     let sig_rptr = sig_ptr.rptr(&env)?;
//     let pub_key = rptr.typed_ref::<PublicKey>()?;
//     let signature = sig_rptr.typed_ref::<PublicKey>()?;
//     env
//       .convert_byte_array(data)
//       .into_result()
//       .and_then(|data| (pub_key.verify(data, signature)).into_result())
//       .and_then(|val| (val as jboolean).jobject(&env))
//   })
//   .jresult(&env)
// }

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_publicKeyHash(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<PublicKey>().and_then(|pkey| pkey.hash().rptr().jptr(&env))
  })
  .jresult(&env)
}
