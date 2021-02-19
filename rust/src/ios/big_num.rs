use super::result::CResult;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::utils::{BigNum};


#[no_mangle]
pub unsafe extern "C" fn big_num_from_str(
  chars: CharPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| BigNum::from_str(chars.into_str()).map(|big_num| big_num.rptr()).into_result())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn big_num_to_str(
  big_num: RPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| big_num.typed_ref::<BigNum>().map(|big_num| big_num.to_str().into_cstr()))
    .response(result, error)
}

// #[no_mangle]
// pub unsafe extern "C" fn value_from_u64(u: u64, result: &mut RPtr, error: &mut CharPtr) -> bool {
//   handle_exception(|| Value::from(u).rptr()).response(result, error)
// }

#[no_mangle]
pub unsafe extern "C" fn big_num_checked_add(
  big_num: RPtr, other: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let val = big_num.typed_ref::<BigNum>()?;
    let oth = other.typed_ref::<BigNum>()?;
    val.checked_add(oth).map(|val| val.rptr()).into_result()
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn big_num_checked_sub(
  big_num: RPtr, other: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let val = big_num.typed_ref::<BigNum>()?;
    let oth = other.typed_ref::<BigNum>()?;
    val.checked_sub(oth).into_result().map(|val| val.rptr())
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn big_num_clamped_sub(
  big_num: RPtr, other: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let val = big_num.typed_ref::<BigNum>()?;
    other.typed_ref::<BigNum>()
      .map(|other| val.clamped_sub(other))
      .map(|val| val.rptr())
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn big_num_compare(
  big_num: RPtr, rhs: RPtr, result: &mut i8, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let big_num = big_num.typed_ref::<BigNum>()?;
    rhs.typed_ref::<BigNum>()
      .map(|rhs| big_num.compare(rhs))
  })
  .response(result, error)
}
