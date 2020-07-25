use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jobject, jint};
use jni::JNIEnv;
use cardano_serialization_lib::utils::{BigNum};
use cardano_serialization_lib::fees::{LinearFee};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_linearFeeConstant(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<LinearFee>().and_then(|fee| fee.constant().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_linearFeeCoefficient(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr.typed_ref::<LinearFee>().and_then(|fee| fee.coefficient().rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_linearFeeNew(
  env: JNIEnv, _: JObject, coefficient: JRPtr, constant: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let coefficient = coefficient.rptr(&env)?;
    let constant = constant.rptr(&env)?;
    coefficient.typed_ref::<BigNum>().zip(constant.typed_ref::<BigNum>()).and_then(
      |(coefficient, constant)| {
        LinearFee::new(coefficient, constant).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}
