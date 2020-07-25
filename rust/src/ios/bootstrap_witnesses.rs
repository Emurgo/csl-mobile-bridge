use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{BootstrapWitness, BootstrapWitnesses};

#[no_mangle]
pub extern "C" fn bootstrap_witnesses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| BootstrapWitnesses::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_len(
  witnesses: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| witnesses.typed_ref::<BootstrapWitnesses>().map(|witnesses| witnesses.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_add(
  witnesses: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    witnesses
      .typed_ref::<BootstrapWitnesses>()
      .zip(item.typed_ref::<BootstrapWitness>())
      .map(|(witnesses, item)| witnesses.add(item))
  })
  .response(&mut (), error)
}
