use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject};
use jni::JNIEnv;
use cardano_serialization_lib::crypto::{PublicKey, Vkey};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_vkeyNew(
  env: JNIEnv, _: JObject, pk: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let pk = pk.rptr(&env)?;
    pk.typed_ref::<PublicKey>()
    .and_then(|pk| Vkey::new(pk).rptr().jptr(&env))
  })
  .jresult(&env)
}
