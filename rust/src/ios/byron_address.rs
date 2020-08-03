use super::result::CResult;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{Address, ByronAddress};

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
