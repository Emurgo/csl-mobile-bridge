use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::tx_builder::{TransactionBuilder};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};
use cardano_serialization_lib::crypto::{Ed25519KeyHash};
use cardano_serialization_lib::address::ByronAddress;
use cardano_serialization_lib::{TransactionInput, TransactionOutput};

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_key_input(
  tx_builder: RPtr, hash: RPtr, input: RPtr, amount: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<Ed25519KeyHash>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Coin>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_key_input(hash, input, amount))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_bootstrap_input(
  tx_builder: RPtr, hash: RPtr, input: RPtr, amount: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<ByronAddress>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Coin>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_bootstrap_input(hash, input, amount))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_output(
  tx_builder: RPtr, output: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(output.typed_ref::<TransactionOutput>())
      .map(|(tx_builder, output)| tx_builder.add_output(output))
  })
  .map(|_| {})
  .response(&mut (), error)
}

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
