use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::crypto::{Ed25519KeyHash, ScriptHash};

impl ToFromBytes for StakeCredential {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<StakeCredential, DeserializeError> {
    StakeCredential::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_from_keyhash(
  keyhash: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    keyhash
      .typed_ref::<Ed25519KeyHash>()
      .map(|keyhash| StakeCredential::from_keyhash(keyhash))
  })
    .map(|stake_credential| stake_credential.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_from_scripthash(
  scripthash: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    scripthash
      .typed_ref::<ScriptHash>()
      .map(|scripthash| StakeCredential::from_scripthash(scripthash))
  })
    .map(|stake_credential| stake_credential.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_to_keyhash(
  stake_credential: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_credential
      .typed_ref::<StakeCredential>()
      .map(|stake_credential| stake_credential.to_keyhash())
  })
    .map(|keyhash| keyhash.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_to_scripthash(
  stake_credential: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_credential
      .typed_ref::<StakeCredential>()
      .map(|stake_credential| stake_credential.to_scripthash())
  })
    .map(|scripthash| scripthash.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_to_kind(
  stake_credential: RPtr, result: &mut u8, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_credential.typed_ref::<StakeCredential>().map(|stake_credential| stake_credential.kind())
  })
  .map(|stake_credential_kind| stake_credential_kind.into())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_to_bytes(
  stake_credential: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<StakeCredential>(stake_credential, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn stake_credential_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<StakeCredential>(data, len, result, error)
}
