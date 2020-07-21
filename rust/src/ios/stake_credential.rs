use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{StakeCredential};
use cardano_serialization_lib::crypto::{Ed25519KeyHash};

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

// TODO
// pub unsafe extern "C" fn stake_credential_from_scripthash

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

// TODO
// pub unsafe extern "C" fn stake_credential_to_scripthash

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
