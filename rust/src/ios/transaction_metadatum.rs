use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception_result};
use crate::ptr::RPtrRepresentable;
use crate::ptr::{RPtr};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{TransactionMetadatum, MetadataList};

impl ToFromBytes for TransactionMetadatum {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionMetadatum, DeserializeError> {
    TransactionMetadatum::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_to_bytes(
  transaction_metadatum: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionMetadatum>(transaction_metadatum, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionMetadatum>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_list(
  metadata_list: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_list
      .typed_ref::<MetadataList>()
      .map(|metadata_list| TransactionMetadatum::new_list(metadata_list))
  })
    .map(|transaction_metadatum| transaction_metadatum.rptr())
    .response(result, error)
}
