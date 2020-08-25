use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::{StakeDeregistration};

impl ToFromBytes for StakeDeregistration {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeDeregistration, DeserializeError> {
    StakeDeregistration::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_to_bytes(
  stake_deregistration: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<StakeDeregistration>(stake_deregistration, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<StakeDeregistration>(data, len, result, error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_new(
  stake_cred_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_cred_ptr
      .typed_ref::<StakeCredential>()
      .map(|stake_cred| StakeDeregistration::new(stake_cred))
  })
    .map(|stake_dereg| stake_dereg.rptr())
    .response(result, error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_stake_credential(
  stake_deregistration: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_deregistration
      .typed_ref::<StakeDeregistration>()
      .map(|stake_deregistration| stake_deregistration.stake_credential())
  })
    .map(|stake_cred| stake_cred.rptr())
    .response(result, error)
}
