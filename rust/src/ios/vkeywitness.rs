use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{Vkeywitness, Vkey, Ed25519Signature};

#[no_mangle]
pub unsafe extern "C" fn vkeywitness_new(
  vkey: RPtr, signature: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    vkey
      .typed_ref::<Vkey>()
      .zip(
        signature.typed_ref::<Ed25519Signature>()
      )
      .map(|(vkey, signature)| {
        Vkeywitness::new(vkey, signature)
      })
    })
    .map(|vkeywit| vkeywit.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn vkeywitness_signature(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<Vkeywitness>()
      .map(|vkeywit| vkeywit.signature())
    })
    .map(|signature| signature.rptr())
    .response(result, error)
}
