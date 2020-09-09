use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::crypto::{Vkeywitness, Vkey, Ed25519Signature};

impl ToFromBytes for Vkeywitness {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Vkeywitness, DeserializeError> {
    Vkeywitness::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn vkeywitness_to_bytes(
  vkeywitness: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<Vkeywitness>(vkeywitness, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn vkeywitness_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<Vkeywitness>(data, len, result, error)
}

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
