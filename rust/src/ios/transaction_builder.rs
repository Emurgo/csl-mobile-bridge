use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::tx_builder::{TransactionBuilder};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_new(
  linear_fee: RPtr, minimum_utxo_val: RPtr, pool_deposit: RPtr, key_deposit: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    linear_fee
      .typed_ref::<LinearFee>()
      .zip(minimum_utxo_val.typed_ref::<Coin>())
      .zip(pool_deposit.typed_ref::<BigNum>())
      .zip(key_deposit.typed_ref::<BigNum>())
      .map(|(((linear_fee, minimum_utxo_val), pool_deposit), key_deposit)| {
        TransactionBuilder::new(linear_fee, minimum_utxo_val, pool_deposit, key_deposit)
      })
    })
    .map(|fee| fee.rptr())
    .response(result, error)
}
