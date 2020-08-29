use crate::utils::ToFromBytes;
use super::result::CResult;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use super::string::{CharPtr};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::panic::{handle_exception_result, Zip};
use cardano_serialization_lib::TransactionOutput;
use cardano_serialization_lib::error::DeserializeError;
use cardano_serialization_lib::address::Address;
use cardano_serialization_lib::utils::BigNum;

impl ToFromBytes for TransactionOutput {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionOutput, DeserializeError> {
    TransactionOutput::from_bytes(bytes)
  }

}

#[no_mangle]
pub unsafe extern "C" fn transaction_output_to_bytes(
  transaction_output: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionOutput>(transaction_output, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_output_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionOutput>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_output_new(
  address: RPtr, amount: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    address
      .typed_ref::<Address>()
      .zip(
        amount.typed_ref::<BigNum>()
      )
      .map(|(address, amount)| {
        TransactionOutput::new(address, amount)
      })
    })
    .map(|tx_output| tx_output.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionOutput>()
      .map(|tx_output| tx_output.amount())
    })
    .map(|amount| amount.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_output_address(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionOutput>()
      .map(|tx_output| tx_output.address())
    })
    .map(|address| address.rptr())
    .response(result, error)
}
