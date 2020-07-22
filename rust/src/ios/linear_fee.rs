use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::utils::{BigNum};
use cardano_serialization_lib::fees::{LinearFee};

#[no_mangle]
pub unsafe extern "C" fn linear_fee_coefficient(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<LinearFee>()
      .map(|fee| fee.coefficient())
    })
    .map(|coeff| coeff.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn linear_fee_constant(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<LinearFee>()
      .map(|fee| fee.constant())
    })
    .map(|constant| constant.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn linear_fee_new(
  coefficient: RPtr, constant: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    coefficient
      .typed_ref::<BigNum>()
      .zip(
        constant.typed_ref::<BigNum>()
      )
      .map(|(coefficient, constant)| {
        LinearFee::new(coefficient, constant)
      })
    })
    .map(|fee| fee.rptr())
    .response(result, error)
}
