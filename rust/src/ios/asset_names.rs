/**
 * AssetNames
 */

use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{AssetName, AssetNames};

#[no_mangle]
pub extern "C" fn asset_names_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| AssetNames::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_names_len(
  asset_names: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| asset_names.typed_ref::<AssetNames>().map(|asset_names| asset_names.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_names_get(
  asset_names: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    asset_names.typed_ref::<AssetNames>().map(|asset_names| asset_names.get(index))
  })
  .map(|asset_name| asset_name.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn asset_names_add(
  asset_names: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    asset_names
      .typed_ref::<AssetNames>()
      .zip(item.typed_ref::<AssetName>())
      .map(|(asset_names, item)| asset_names.add(item))
  })
  .response(&mut (), error)
}
