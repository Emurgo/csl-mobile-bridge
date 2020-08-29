use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{TransactionOutputs};


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_len(
  tx_outputs: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| tx_outputs.typed_ref::<TransactionOutputs>().map(|tx_outputs| tx_outputs.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_get(
  tx_outputs: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_outputs.typed_ref::<TransactionOutputs>().map(|tx_outputs| tx_outputs.get(index))
  })
  .map(|tx_output| tx_output.rptr())
  .response(result, error)
}
