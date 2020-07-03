use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr, IntoCString, IntoStr};
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cddl_lib::address::{StakeCredential};
use cddl_lib::crypto::{AddrKeyHash};

#[no_mangle]
pub unsafe extern "C" fn stake_credential_from_keyhash(
  keyhash: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    keyhash
      // .owned::<AddrKeyHash>()
      .typed_ref::<AddrKeyHash>()
      .map(|keyhash| StakeCredential::from_keyhash(keyhash))
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
pub unsafe extern "C" fn stake_credential_to_kind(
  stake_credential: RPtr, result: &mut u8, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    stake_credential.typed_ref::<StakeCredential>().map(|stake_credential| stake_credential.kind())
  })
  .map(|stake_credential_kind| stake_credential_kind.into())
  .response(result, error)
}
