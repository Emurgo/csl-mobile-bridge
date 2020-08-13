use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::{StakeRegistration};

impl ToFromBytes for StakeRegistration {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeRegistration, DeserializeError> {
    StakeRegistration::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn stake_registration_to_bytes(
  stake_registration: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<StakeRegistration>(stake_registration, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_registration_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<StakeRegistration>(data, len, result, error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_new(
  stake_cred_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_cred_ptr
      .typed_ref::<StakeCredential>()
      .map(|stake_cred| StakeRegistration::new(stake_cred))
  })
    .map(|stake_reg| stake_reg.rptr())
    .response(result, error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_stake_credential(
  stake_registration: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_registration
      .typed_ref::<StakeRegistration>()
      .map(|stake_registration| stake_registration.stake_credential())
  })
    .map(|stake_cred| stake_cred.rptr())
    .response(result, error)
}
