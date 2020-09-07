use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{TransactionInputs, TransactionInput};


// TODO: obj-c/js wrappers
#[no_mangle]
pub extern "C" fn transaction_inputs_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| TransactionInputs::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_len(
  transaction_inputs: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| transaction_inputs.typed_ref::<TransactionInputs>().map(|transaction_inputs| transaction_inputs.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_get(
  tx_inputs: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_inputs.typed_ref::<TransactionInputs>().map(|tx_inputs| tx_inputs.get(index))
  })
  .map(|tx_input| tx_input.rptr())
  .response(result, error)
}

// TODO: obj-c/js wrappers
#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_add(
  transaction_inputs: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_inputs
      .typed_ref::<TransactionInputs>()
      .zip(item.typed_ref::<TransactionInput>())
      .map(|(transaction_inputs, item)| transaction_inputs.add(item))
  })
  .response(&mut (), error)
}
