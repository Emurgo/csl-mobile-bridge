use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{Ed25519Signature};

#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_to_bytes(
  ed25519_signature: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    ed25519_signature.typed_ref::<Ed25519Signature>().map(|ed25519_signature| ed25519_signature.to_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Ed25519Signature::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|ed25519_signature| ed25519_signature.rptr())
  .response(result, error)
}
