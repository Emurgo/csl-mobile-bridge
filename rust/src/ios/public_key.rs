use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr, IntoStr, IntoCString};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::cardano_serialization_lib::crypto::PublicKey;

#[no_mangle]
pub unsafe extern "C" fn public_key_from_bech32(
  bech32_str: CharPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    PublicKey::from_bech32(bech32_str.into_str()).map(|pkey| pkey.rptr()).into_result()
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_to_bech32(
  public_key: RPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    public_key
      .typed_ref::<PublicKey>()
      .map(|public_key| public_key.to_bech32())
  })
  .map(|bech32| bech32.into_cstr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    PublicKey::from_bytes(std::slice::from_raw_parts(data, len)).into_result()
  })
  .map(|public_key| public_key.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_as_bytes(
  pub_key: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| pub_key.typed_ref::<PublicKey>().map(|pkey| pkey.as_bytes().into()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_hash(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<PublicKey>()
      .map(|pkey| pkey.hash())
    })
    .map(|hash| hash.rptr())
    .response(result, error)
}
