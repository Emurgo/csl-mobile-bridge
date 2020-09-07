use super::result::CResult;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use super::string::{CharPtr};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::panic::{handle_exception_result};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{TransactionBody};

impl ToFromBytes for TransactionBody {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionBody, DeserializeError> {
    TransactionBody::from_bytes(bytes)
  }

}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_to_bytes(
  transaction_body: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionBody>(transaction_body, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionBody>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_inputs(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.inputs())
    })
    .map(|tx_inputs| tx_inputs.rptr())
    .response(result, error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_outputs(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.outputs())
    })
    .map(|tx_outputs| tx_outputs.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_fee(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.fee())
    })
    .map(|fee| fee.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_ttl(
  rptr: RPtr, result: &mut u32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.ttl())
    })
    .map(|ttl| ttl.into())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_certs(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.certs())
    })
    .map(|certs| certs.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_body_withdrawals(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBody>()
      .map(|tx_body| tx_body.withdrawals())
    })
    .map(|withdrawals| withdrawals.rptr())
    .response(result, error)
}
