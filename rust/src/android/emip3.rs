use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult};
use jni::objects::{JObject, JString};
use jni::sys::{jobject};
use jni::JNIEnv;

use cardano_serialization_lib::emip3::*;

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encryptWithPassword(
  env: JNIEnv, _: JObject, password: JString, salt: JString, nonce: JString, data: JString
) -> jobject {
  handle_exception_result(|| {
    let password = password.string(&env)?;
    let salt = salt.string(&env)?;
    let nonce = nonce.string(&env)?;
    let data = data.string(&env)?;

    let output = encrypt_with_password(&password, &salt, &nonce, &data).into_result()?;
    output.jstring(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decryptWithPassword(
  env: JNIEnv, _: JObject, password: JString, data: JString
) -> jobject {
  handle_exception_result(|| {
    let password = password.string(&env)?;
    let data = data.string(&env)?;

    let output = decrypt_with_password(&password, &data).into_result()?;
    output.jstring(&env)
  })
  .jresult(&env)
}
