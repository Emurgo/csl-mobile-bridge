use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr, IntoCString, IntoStr};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::Bip32PublicKey;
use std::convert::TryFrom;

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_derive(
  bip32_public_key: RPtr, index: i64, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let idx_u32 = u32::try_from(index).map_err(|err| err.to_string())?;
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .and_then(|bip32_public_key| bip32_public_key.derive(idx_u32).into_result())
  })
  .map(|bip32_public_key| bip32_public_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_to_raw_key(
  bip32_public_key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.to_raw_key())
  })
  .map(|public_key| public_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Bip32PublicKey::from_bytes(std::slice::from_raw_parts(data, len)).into_result()
  })
  .map(|bip32_public_key| bip32_public_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_as_bytes(
  bip32_public_key: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.as_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

#[no_mangle]
pub extern "C" fn bip32_public_key_from_bech32(
  bech32_str: CharPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| Bip32PublicKey::from_bech32(bech32_str.into_str()).into_result())
    .map(|bip32_public_key| bip32_public_key.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_to_bech32(
  bip32_public_key: RPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.to_bech32())
  })
  .map(|bech32| bech32.into_cstr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_chaincode(
  bip32_public_key: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip32_public_key
      .typed_ref::<Bip32PublicKey>()
      .map(|bip32_public_key| bip32_public_key.chaincode())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}
