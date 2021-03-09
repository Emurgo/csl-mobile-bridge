use super::result::CResult;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::utils::{Int, BigNum};


#[no_mangle]
pub unsafe extern "C" fn int_new(
  x: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    x.typed_ref::<BigNum>()
      .map(|x| Int::new(x))
  })
    .map(|val| val.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn int_as_i32(
  int: RPtr, result: &mut i32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    int.typed_ref::<Int>()
      .map(|int| int.as_i32())
  }).response(result, error)
}
