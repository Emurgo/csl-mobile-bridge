use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{UnitInterval};
use cardano_serialization_lib::utils::{BigNum};

#[no_mangle]
pub unsafe extern "C" fn unit_interval_to_bytes(
  unit_interval: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| unit_interval.typed_ref::<UnitInterval>().map(|unit_interval| unit_interval.to_bytes()))
  .map(|bytes| bytes.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn unit_interval_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    UnitInterval::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|unit_interval| unit_interval.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn unit_interval_new(
  numerator: RPtr, denominator: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    numerator
      .typed_ref::<BigNum>()
      .zip(
        denominator.typed_ref::<BigNum>()
      )
      .map(|(numerator, denominator)| {
        UnitInterval::new(numerator, denominator)
      })
  })
  .map(|unit_interval| unit_interval.rptr())
  .response(result, error)
}
