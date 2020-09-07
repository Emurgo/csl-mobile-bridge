use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, handle_exception, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::RewardAddress;
use cardano_serialization_lib::Withdrawals;
use cardano_serialization_lib::utils::{Coin};

#[no_mangle]
pub extern "C" fn withdrawals_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| Withdrawals::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn withdrawals_len(
  withdrawals: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| withdrawals.typed_ref::<Withdrawals>().map(|withdrawals| withdrawals.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn withdrawals_insert(
  withdrawals: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    withdrawals
      .typed_ref::<Withdrawals>()
      .zip(key.typed_ref::<RewardAddress>())
      .zip(value.typed_ref::<Coin>())
      .map(|((withdrawals, key), value)| withdrawals.insert(key, value))
  })
  .map(|coin| coin.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn withdrawals_get(
  withdrawals: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    withdrawals
      .typed_ref::<Withdrawals>()
      .zip(key.typed_ref::<RewardAddress>())
      .map(|(withdrawals, key)| withdrawals.get(key))
    })
    .map(|coin| coin.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn withdrawals_keys(
  withdrawals: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    withdrawals
      .typed_ref::<Withdrawals>()
      .map(|withdrawals| withdrawals.keys())
    })
    .map(|reward_addresses| reward_addresses.rptr())
    .response(result, error)
}
