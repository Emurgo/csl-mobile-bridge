use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::crypto::{Ed25519KeyHash};
use cardano_serialization_lib::{StakeDelegation};

impl ToFromBytes for StakeDelegation {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeDelegation, DeserializeError> {
    StakeDelegation::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn stake_delegation_to_bytes(
  stake_delegation: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<StakeDelegation>(stake_delegation, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_delegation_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<StakeDelegation>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_delegation_stake_credential(
  stake_delegation: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_delegation
      .typed_ref::<StakeDelegation>()
      .map(|stake_delegation| stake_delegation.stake_credential())
  })
    .map(|stake_cred| stake_cred.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_delegation_pool_keyhash(
  stake_delegation: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_delegation
      .typed_ref::<StakeDelegation>()
      .map(|stake_delegation| stake_delegation.pool_keyhash())
  })
    .map(|key_hash| key_hash.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_delegation_new(
  stake_cred_ptr: RPtr, pool_keyhash_ptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_cred_ptr
      .typed_ref::<StakeCredential>()
      .zip(pool_keyhash_ptr.typed_ref::<Ed25519KeyHash>())
      .map(|(stake_cred, pool_keyhash)| StakeDelegation::new(stake_cred, pool_keyhash))
  })
    .map(|stake_delegation| stake_delegation.rptr())
    .response(result, error)
}
