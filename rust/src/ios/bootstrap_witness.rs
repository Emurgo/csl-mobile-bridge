use std::slice::from_raw_parts;
use super::result::CResult;
use super::string::*;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::DeserializeError;
use cardano_serialization_lib::crypto::{BootstrapWitness, Vkey, Ed25519Signature};

impl ToFromBytes for BootstrapWitness {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<BootstrapWitness, DeserializeError> {
    BootstrapWitness::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_to_bytes(
  bootstrap_witness: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<BootstrapWitness>(bootstrap_witness, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<BootstrapWitness>(data, len, result, error)
}

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
