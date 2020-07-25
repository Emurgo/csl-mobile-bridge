use super::result::CResult;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{ByronAddress};

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
