use std::convert::TryFrom;
use super::result::CResult;
use super::data::DataPtr;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{Address, ByronAddress};
use cardano_serialization_lib::crypto::Bip32PublicKey;

#[no_mangle]
pub unsafe extern "C" fn byron_address_to_base58(
  rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| rptr.typed_ref::<ByronAddress>().map(|addr| addr.to_base58().into_cstr()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_from_base58(
  chars: CharPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| ByronAddress::from_base58(chars.into_str()).map(|addr| addr.rptr()).into_result())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_is_valid(
  chars: CharPtr, result: &mut bool, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Ok(ByronAddress::is_valid(chars.into_str()))
  })
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_to_address(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<ByronAddress>()
      .map(|byron_addr| byron_addr.to_address())
    })
    .map(|addr| addr.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_from_address(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<Address>()
      .map(|addr| ByronAddress::from_address(addr))
    })
    .map(|byron_address| byron_address.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_byron_protocol_magic(
  rptr: RPtr, result: &mut u32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<ByronAddress>()
      .map(|addr| addr.byron_protocol_magic())
  })
  .map(|protocol_magic| protocol_magic.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_attributes(
  rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| rptr.typed_ref::<ByronAddress>().map(|byron_addr| byron_addr.attributes()))
  .map(|bytes| bytes.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn byron_address_icarus_from_key(
  key_rptr: RPtr, protocol_magic: i64, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let magic_u32 = u32::try_from(protocol_magic).map_err(|err| err.to_string())?;
    key_rptr
      .typed_ref::<Bip32PublicKey>()
      .map(|key| ByronAddress::icarus_from_key(key, magic_u32))
    })
    .map(|byron_address| byron_address.rptr())
    .response(result, error)
}
