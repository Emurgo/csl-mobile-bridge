use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{TransactionMetadata, TransactionMetadatum, TransactionMetadatumLabels};
use cardano_serialization_lib::utils::{BigNum};

pub type TransactionMetadatumLabel = BigNum;

impl ToFromBytes for TransactionMetadata {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadata, DeserializeError> {
    TransactionMetadata::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_to_bytes(
  transaction_metadata: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionMetadata>(transaction_metadata, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionMetadata>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn transaction_metadata_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| TransactionMetadata::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_len(
  transaction_metadata: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadata
      .typed_ref::<TransactionMetadata>()
      .map(|transaction_metadata| transaction_metadata.len())
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_insert(
  transaction_metadata: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadata
      .typed_ref::<TransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .zip(value.typed_ref::<TransactionMetadatum>())
      .map(|((transaction_metadata, key), value)| transaction_metadata.insert(key, value))
  })
  .map(|value| value.rptr()) // return TransactionMetadatum
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_get(
  transaction_metadata: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadata
      .typed_ref::<TransactionMetadata>()
      .zip(key.typed_ref::<TransactionMetadatumLabel>())
      .map(|(transaction_metadata, key)| transaction_metadata.get(key))
    })
    .map(|tx_metadatum| tx_metadatum.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadata_keys(
  transaction_metadata: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadata
      .typed_ref::<TransactionMetadata>()
      .map(|transaction_metadata| transaction_metadata.keys())
    })
    .map(|tx_metadatum_labels| tx_metadatum_labels.rptr())
    .response(result, error)
}
