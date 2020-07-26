use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{Vkeywitness, Vkeywitnesses};

#[no_mangle]
pub extern "C" fn vkeywitnesses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| Vkeywitnesses::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_len(
  witnesses: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| witnesses.typed_ref::<Vkeywitnesses>().map(|witnesses| witnesses.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_add(
  witnesses: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    witnesses
      .typed_ref::<Vkeywitnesses>()
      .zip(item.typed_ref::<Vkeywitness>())
      .map(|(witnesses, item)| witnesses.add(item))
  })
  .response(&mut (), error)
}
