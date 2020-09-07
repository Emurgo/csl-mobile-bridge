use std::slice::from_raw_parts;
use super::data::DataPtr;
use super::result::CResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{BootstrapWitness, Vkey, Ed25519Signature};


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_new(
  vkey: RPtr, signature: RPtr, chain_code: *const u8, chain_code_len: usize, attributes: *const u8, attributes_len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    vkey.typed_ref::<Vkey>()
      .zip(signature.typed_ref::<Ed25519Signature>())
      .map(|(vkey, signature)| {
        BootstrapWitness::new(vkey, signature, from_raw_parts(chain_code, chain_code_len).into(), from_raw_parts(attributes, attributes_len).into())
      })
  })
  .map(|bootstrap_witness| bootstrap_witness.rptr())
  .response(result, error)
}
