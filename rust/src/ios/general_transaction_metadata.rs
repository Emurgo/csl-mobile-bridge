use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{GeneralTransactionMetadata, TransactionMetadatum};
use cardano_serialization_lib::utils::{BigNum};

pub type TransactionMetadatumLabel = BigNum;

impl ToFromBytes for GeneralTransactionMetadata {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<GeneralTransactionMetadata, DeserializeError> {
    GeneralTransactionMetadata::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_to_bytes(
  general_transaction_metadata: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<GeneralTransactionMetadata>(general_transaction_metadata, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<GeneralTransactionMetadata>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn general_transaction_metadata_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| GeneralTransactionMetadata::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_len(
  general_transaction_metadata: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .map(|general_transaction_metadata| general_transaction_metadata.len())
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_insert(
  general_transaction_metadata: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .zip(value.typed_ref::<TransactionMetadatum>())
      .map(|((general_transaction_metadata, key), value)| general_transaction_metadata.insert(key, value))
  })
  .map(|value| value.rptr()) // return TransactionMetadatum
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_get(
  general_transaction_metadata: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .map(|(general_transaction_metadata, key)| general_transaction_metadata.get(key))
    })
    .map(|tx_metadatum| tx_metadatum.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_keys(
  general_transaction_metadata: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    general_transaction_metadata
      .typed_ref::<GeneralTransactionMetadata>()
      .map(|general_transaction_metadata| general_transaction_metadata.keys())
    })
    .map(|tx_metadatum_labels| tx_metadatum_labels.rptr())
    .response(result, error)
}
