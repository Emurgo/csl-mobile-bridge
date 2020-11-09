use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::utils::{BigNum};
use cardano_serialization_lib::metadata::{TransactionMetadatumLabels};

impl ToFromBytes for TransactionMetadatumLabels {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadatumLabels, DeserializeError> {
    TransactionMetadatumLabels::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_to_bytes(
  transaction_metadatum_labels: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionMetadatumLabels>(transaction_metadatum_labels, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionMetadatumLabels>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn transaction_metadatum_labels_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| TransactionMetadatumLabels::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_len(
  transaction_metadatum_labels: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| transaction_metadatum_labels.typed_ref::<TransactionMetadatumLabels>().map(|certs| certs.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_get(
  transaction_metadatum_labels: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadatum_labels.typed_ref::<TransactionMetadatumLabels>().map(|transaction_metadatum_labels| transaction_metadatum_labels.get(index))
  })
  .map(|transaction_metadatum_label| transaction_metadatum_label.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_add(
  transaction_metadatum_labels: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_metadatum_labels
      .typed_ref::<TransactionMetadatumLabels>()
      .zip(item.typed_ref::<BigNum>())
      .map(|(transaction_metadatum_labels, item)| transaction_metadatum_labels.add(item))
  })
  .response(&mut (), error)
}
