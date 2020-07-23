use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr, IntoCString, IntoStr};
use crate::panic::{handle_exception, handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::Bip32PrivateKey;
use std::convert::TryFrom;

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_derive(
  bip_32_private_key: RPtr, index: i64, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let idx_u32 = u32::try_from(index).map_err(|err| err.to_string())?;
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.derive(idx_u32))
  })
  .map(|bip_32_private_key| bip_32_private_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_generate_ed25519_bip32(
  result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| Bip32PrivateKey::generate_ed25519_bip32().into_result())
    .map(|bip_32_private_key| bip_32_private_key.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_to_raw_key(
  bip_32_private_key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.to_raw_key())
  })
  .map(|private_key| private_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_to_public(
  bip_32_private_key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.to_public())
  })
  .map(|bip_32_public_key| bip_32_public_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Bip32PrivateKey::from_bytes(std::slice::from_raw_parts(data, len)).into_result()
  })
  .map(|bip_32_private_key| bip_32_private_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_as_bytes(
  bip_32_private_key: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.as_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

#[no_mangle]
pub extern "C" fn bip_32_private_key_from_bech32(
  bech32_str: CharPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| Bip32PrivateKey::from_bech32(bech32_str.into_str()).into_result())
    .map(|bip_32_private_key| bip_32_private_key.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_to_bech32(
  bip_32_private_key: RPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    bip_32_private_key
      .typed_ref::<Bip32PrivateKey>()
      .map(|bip_32_private_key| bip_32_private_key.to_bech32())
  })
  .map(|bech32| bech32.into_cstr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bip_32_private_key_from_bip39_entropy(
  entropy_data: *const u8, entropy_len: usize, password_data: *const u8, password_len: usize,
  result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception(|| {
    Bip32PrivateKey::from_bip39_entropy(
      std::slice::from_raw_parts(entropy_data, entropy_len),
      std::slice::from_raw_parts(password_data, password_len)
    )
  })
  .map(|bip_32_private_key| bip_32_private_key.rptr())
  .response(result, error)
}
