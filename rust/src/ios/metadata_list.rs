use super::result::CResult;
use super::string::CharPtr;
use super::data::DataPtr;
use super::utils::{to_bytes, from_bytes};
use crate::utils::ToFromBytes;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::metadata::{MetadataList, TransactionMetadatum};
use cardano_serialization_lib::error::{DeserializeError};

impl ToFromBytes for MetadataList {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<MetadataList, DeserializeError> {
    MetadataList::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn metadata_list_to_bytes(
  metadata_list: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<MetadataList>(metadata_list, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_list_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<MetadataList>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn metadata_list_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| MetadataList::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_list_len(
  metadata_list: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| metadata_list.typed_ref::<MetadataList>().map(|metadata_list| metadata_list.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_list_get(
  metadata_list: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_list.typed_ref::<MetadataList>().map(|metadata_list| metadata_list.get(index))
  })
  .map(|tx_metadatum| tx_metadatum.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_list_add(
  metadata_list: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_list
      .typed_ref::<MetadataList>()
      .zip(item.typed_ref::<TransactionMetadatum>())
      .map(|(metadata_list, item)| metadata_list.add(item))
  })
  .response(&mut (), error)
}
