
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
