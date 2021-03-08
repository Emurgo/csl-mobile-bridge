use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::metadata::{MetadataMap, TransactionMetadatum};

#[no_mangle]
pub extern "C" fn metadata_map_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| MetadataMap::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_map_len(
  metadata_map: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| metadata_map.typed_ref::<MetadataMap>().map(|metadata_map| metadata_map.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_map_insert(
  metadata_map: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_map
      .typed_ref::<MetadataMap>()
      .zip(key.typed_ref::<TransactionMetadatum>())
      .zip(value.typed_ref::<TransactionMetadatum>())
      .map(|((metadata_map, key), value)| metadata_map.insert(key, value))
  })
  .map(|tx_metadatum| tx_metadatum.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_map_get(
  metadata_map: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_map
      .typed_ref::<MetadataMap>()
      .zip(key.typed_ref::<TransactionMetadatum>())
      .and_then(|(metadata_map, key)| metadata_map.get(key).into_result())
    })
    .map(|tx_metadatum| tx_metadatum.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn metadata_map_keys(
  metadata_map: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    metadata_map
      .typed_ref::<MetadataMap>()
      .map(|metadata_map| metadata_map.keys())
    })
    .map(|metadata_list| metadata_list.rptr())
    .response(result, error)
}
