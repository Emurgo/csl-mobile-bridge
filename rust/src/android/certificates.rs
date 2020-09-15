use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use jni::objects::JObject;
use jni::sys::{jobject, jbyteArray, jlong};
use jni::JNIEnv;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{Certificate, Certificates};

impl ToFromBytes for Certificates {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Certificates, DeserializeError> {
    Certificates::from_bytes(bytes)
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesToBytes(
  env: JNIEnv, _: JObject, certificates: JRPtr
) -> jobject {
  to_bytes::<Certificates>(env, certificates)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesFromBytes(
  env: JNIEnv, _: JObject, bytes: jbyteArray
) -> jobject {
  from_bytes::<Certificates>(env, bytes)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesNew(
  env: JNIEnv, _: JObject
) -> jobject {
  handle_exception_result(|| Certificates::new().rptr().jptr(&env)).jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesLen(
  env: JNIEnv, _: JObject, certificates: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let certificates = certificates.rptr(&env)?;
    certificates
      .typed_ref::<Certificates>()
      .map(|certificates| certificates.len())
      .and_then(|len| len.into_jlong().jobject(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesGet(
  env: JNIEnv, _: JObject, certificates: JRPtr, index: jlong
) -> jobject {
  handle_exception_result(|| {
    let certificates = certificates.rptr(&env)?;
    certificates
      .typed_ref::<Certificates>()
      .map(|certificates| certificates.get(usize::from_jlong(index)))
      .and_then(|certificate| certificate.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_certificatesAdd(
  env: JNIEnv, _: JObject, certificates: JRPtr, item: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let certificates = certificates.rptr(&env)?;
    let item = item.rptr(&env)?;
    certificates
      .typed_ref::<Certificates>()
      .zip(item.typed_ref::<Certificate>())
      .map(|(certificates, item)| certificates.add(item))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}
