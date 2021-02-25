/**
 * AssetName
 */

use super::result::CResult;
use super::data::DataPtr;
use super::string::CharPtr;
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{AssetName};

impl ToFromBytes for AssetName {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<AssetName, DeserializeError> {
    AssetName::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn asset_name_to_bytes(
  asset_name: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<AssetName>(asset_name, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_name_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<AssetName>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_name_new(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    AssetName::new(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|asset_name| asset_name.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_name_name(
  asset_name: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    asset_name.typed_ref::<AssetName>().map(|asset_name| asset_name.name())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}
