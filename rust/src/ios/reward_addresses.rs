use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::address::RewardAddress;


#[no_mangle]
pub extern "C" fn reward_addresses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| RewardAddresses::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_addresses_len(
  reward_addresses: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| reward_addresses.typed_ref::<RewardAddresses>().map(|reward_addresses| reward_addresses.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_addresses_get(
  reward_addresses: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    reward_addresses.typed_ref::<RewardAddresses>().map(|reward_addresses| reward_addresses.get(index))
  })
  .map(|reward_address| reward_address.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn reward_addresses_add(
  reward_addresses: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    reward_addresses
      .typed_ref::<RewardAddresses>()
      .zip(item.typed_ref::<RewardAddress>())
      .map(|(reward_addresses, item)| reward_addresses.add(item))
  })
  .response(&mut (), error)
}
