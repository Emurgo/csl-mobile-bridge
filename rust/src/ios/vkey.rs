use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{PublicKey, Vkey};

#[no_mangle]
pub unsafe extern "C" fn vkey_new(
  pk: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    pk
      .typed_ref::<PublicKey>()
      .map(|pk| Vkey::new(pk))
    })
    .map(|vkey| vkey.rptr())
    .response(result, error)
}
