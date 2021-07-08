use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{Transaction, TransactionBody, TransactionWitnessSet};
use cardano_serialization_lib::metadata::AuxiliaryData;

impl ToFromBytes for Transaction {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Transaction, DeserializeError> {
    Transaction::from_bytes(bytes)
  }

}

#[no_mangle]
pub unsafe extern "C" fn transaction_to_bytes(
  transaction: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<Transaction>(transaction, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<Transaction>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<Transaction>()
      .map(|tx| tx.body())
    })
    .map(|body| body.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_new(
  body: RPtr, witness_set: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    body
      .typed_ref::<TransactionBody>()
      .zip(
        witness_set.typed_ref::<TransactionWitnessSet>()
      )
      .map(|(body, witness_set)| {
        Transaction::new(body, witness_set, None)
      })
    })
    .map(|tx| tx.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_new_with_auxiliary_data(
  body: RPtr, witness_set: RPtr, auxiliary_data: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let auxiliary_data = auxiliary_data.owned::<AuxiliaryData>()?;
    body
      .typed_ref::<TransactionBody>()
      .zip(
        witness_set.typed_ref::<TransactionWitnessSet>()
      )
      .map(|(body, witness_set)| {
        Transaction::new(body, witness_set, Some(auxiliary_data))
      })
    })
    .map(|tx| tx.rptr())
    .response(result, error)
}
