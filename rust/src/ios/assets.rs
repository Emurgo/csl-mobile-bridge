use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::{Assets, AssetName};
use cardano_serialization_lib::utils::{BigNum};


#[no_mangle]
pub extern "C" fn assets_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| Assets::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn assets_len(
  assets: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| assets.typed_ref::<Assets>().map(|assets| assets.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn assets_insert(
  assets: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    assets
      .typed_ref::<Assets>()
      .zip(key.typed_ref::<AssetName>())
      .zip(value.typed_ref::<BigNum>())
      .map(|((assets, key), value)| assets.insert(key, value))
  })
  .map(|coin| coin.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn assets_get(
  assets: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    assets
      .typed_ref::<Assets>()
      .zip(key.typed_ref::<AssetName>())
      .map(|(assets, key)| assets.get(key))
    })
    .map(|coin| coin.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn assets_keys(
  assets: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    assets
      .typed_ref::<Assets>()
      .map(|assets| assets.keys())
    })
    .map(|asset_names| asset_names.rptr())
    .response(result, error)
}
