use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::address::{EnterpriseAddress, StakeCredential};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_enterpriseAddressNew(
  env: JNIEnv, _: JObject, network: jint, payment: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let payment = payment.rptr(&env)?;
    payment
    .typed_ref::<StakeCredential>()
    .map(|payment| EnterpriseAddress::new(network as u8, payment))
    .and_then(|enterprise_address| enterprise_address.rptr().jptr(&env))
  })
  .jresult(&env)
}
