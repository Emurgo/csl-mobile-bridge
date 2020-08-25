use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{Address, RewardAddress, StakeCredential};

#[no_mangle]
pub unsafe extern "C" fn reward_address_new(
  network: u8, payment: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    payment
      .typed_ref::<StakeCredential>()
      .map(|payment| RewardAddress::new(network, payment))
    })
    .map(|reward_address| reward_address.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_address_payment_cred(
  reward_address: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    reward_address
      .typed_ref::<RewardAddress>()
      .map(|reward_address| reward_address.payment_cred())
    })
    .map(|payment_credential| payment_credential.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_address_to_address(
  reward_address: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    reward_address
      .typed_ref::<RewardAddress>()
      .map(|reward_address| reward_address.to_address())
    })
    .map(|address| address.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_address_from_address(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<Address>()
      .map(|addr| RewardAddress::from_address(addr))
    })
    .map(|reward_address| reward_address.rptr())
    .response(result, error)
}
