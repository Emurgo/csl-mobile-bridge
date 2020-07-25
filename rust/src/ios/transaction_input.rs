use crate::utils::ToFromBytes;
use super::result::CResult;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use super::string::{CharPtr};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::panic::{handle_exception_result};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::TransactionInput;
use cardano_serialization_lib::crypto::TransactionHash;

impl ToFromBytes for TransactionInput {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionInput, DeserializeError> {
    TransactionInput::from_bytes(bytes)
  }

}

#[no_mangle]
pub unsafe extern "C" fn transaction_input_to_bytes(
  transaction_input: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionInput>(transaction_input, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_input_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionInput>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_input_index(
  transaction_input: RPtr, result: &mut u32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_input.typed_ref::<TransactionInput>().map(|tx_input| tx_input.index())
  })
  .map(|index| index.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_input_transaction_id(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionInput>()
      .map(|tx_input| tx_input.transaction_id())
    })
    .map(|tx_id| tx_id.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_input_new(
  transaction_id: RPtr, index: u32, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_id
      .typed_ref::<TransactionHash>()
      .map(|tx_hash| TransactionInput::new(tx_hash, index))
    })
    .map(|tx_input| tx_input.rptr())
    .response(result, error)
}
