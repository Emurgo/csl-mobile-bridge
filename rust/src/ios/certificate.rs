use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{StakeRegistration, StakeDeregistration, StakeDelegation, Certificate};

impl ToFromBytes for Certificate {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Certificate, DeserializeError> {
    Certificate::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn certificate_to_bytes(
  certificate: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<Certificate>(certificate, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<Certificate>(data, len, result, error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_registration(
  stake_reg_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_reg_ptr
      .typed_ref::<StakeRegistration>()
      .map(|stake_reg| Certificate::new_stake_registration(stake_reg))
  })
    .map(|certificate| certificate.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_deregistration(
  stake_dereg_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_dereg_ptr
      .typed_ref::<StakeDeregistration>()
      .map(|stake_dereg| Certificate::new_stake_deregistration(stake_dereg))
  })
    .map(|certificate| certificate.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_delegation(
  stake_delegation_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_delegation_ptr
      .typed_ref::<StakeDelegation>()
      .map(|stake_delegation| Certificate::new_stake_delegation(stake_delegation))
  })
    .map(|certificate| certificate.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_registration(
  certificate: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    certificate
      .typed_ref::<Certificate>()
      .map(|certificate| certificate.as_stake_registration())
  })
    .map(|stake_registration| stake_registration.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_deregistration(
  certificate: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    certificate
      .typed_ref::<Certificate>()
      .map(|certificate| certificate.as_stake_deregistration())
  })
    .map(|stake_deregistration| stake_deregistration.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_delegation(
  certificate: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    certificate
      .typed_ref::<Certificate>()
      .map(|certificate| certificate.as_stake_delegation())
  })
    .map(|stake_delegation| stake_delegation.rptr())
    .response(result, error)
}
