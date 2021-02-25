use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{Assets, PolicyID, MultiAsset};


#[no_mangle]
pub extern "C" fn multi_asset_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| MultiAsset::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn multi_asset_len(
  multi_asset: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| multi_asset.typed_ref::<MultiAsset>().map(|multi_asset| multi_asset.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn multi_asset_insert(
  multi_asset: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    multi_asset
      .typed_ref::<MultiAsset>()
      .zip(key.typed_ref::<PolicyID>())
      .zip(value.typed_ref::<Assets>())
      .map(|((multi_asset, key), value)| multi_asset.insert(key, value))
  })
  .map(|coin| coin.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn multi_asset_get(
  multi_asset: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    multi_asset
      .typed_ref::<MultiAsset>()
      .zip(key.typed_ref::<PolicyID>())
      .map(|(multi_asset, key)| multi_asset.get(key))
    })
    .map(|assets| assets.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn multi_asset_keys(
  multi_asset: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    multi_asset
      .typed_ref::<MultiAsset>()
      .map(|multi_asset| multi_asset.keys())
    })
    .map(|policy_ids| policy_ids.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn multi_asset_sub(
  multi_asset: RPtr, other: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let val = multi_asset.typed_ref::<MultiAsset>()?;
    other.typed_ref::<MultiAsset>()
      .map(|other| val.sub(other))
      .map(|val| val.rptr())
  })
  .response(result, error)
}
