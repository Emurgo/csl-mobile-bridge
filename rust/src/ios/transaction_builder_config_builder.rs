use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::tx_builder::{TransactionBuilderConfigBuilder};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_new(
  linear_fee: RPtr, pool_deposit: RPtr, key_deposit: RPtr, max_value_size: u32, max_tx_size: u32, coins_per_utxo_word: RPtr, prefer_pure_change: u8, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    linear_fee
      .typed_ref::<LinearFee>()
      .zip(pool_deposit.typed_ref::<BigNum>())
      .zip(key_deposit.typed_ref::<BigNum>())
      .zip(coins_per_utxo_word.typed_ref::<Coin>())
      .map(|(((linear_fee, pool_deposit), key_deposit), coins_per_utxo_word)| {
        TransactionBuilderConfigBuilder::new()
          .fee_algo(linear_fee)
          .pool_deposit(pool_deposit)
          .key_deposit(key_deposit)
          .max_value_size(max_value_size)
          .max_tx_size(max_tx_size)
          .coins_per_utxo_word(coins_per_utxo_word)
          .prefer_pure_change(prefer_pure_change != 0)
      })
    })
    .map(|tx_builder_config_builder| tx_builder_config_builder.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_build(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilderConfigBuilder>()
      .and_then(|tx_builder_config_builder| tx_builder_config_builder.build().into_result())
    })
    .map(|tx_builder_config| tx_builder_config.rptr())
    .response(result, error)
}