use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip, ToResult};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jlong, jobject, jint};
use jni::JNIEnv;
use std::convert::TryFrom;
use cardano_serialization_lib::tx_builder::{TransactionBuilderConfigBuilder};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderConfigBuilderNew(
  env: JNIEnv, _: JObject, linear_fee: JRPtr, pool_deposit: JRPtr, key_deposit: JRPtr, max_value_size: jlong, max_tx_size: jlong, coins_per_utxo_word: JRPtr, prefer_pure_change: jint
) -> jobject {
  handle_exception_result(|| {
    let linear_fee = linear_fee.rptr(&env)?;
    let pool_deposit = pool_deposit.rptr(&env)?;
    let key_deposit = key_deposit.rptr(&env)?;
    let max_value_size_u32 = u32::try_from(max_value_size).map_err(|err| err.to_string())?;
    let max_tx_size_u32 = u32::try_from(max_tx_size).map_err(|err| err.to_string())?;
    let coins_per_utxo_word = coins_per_utxo_word.rptr(&env)?;
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
          .max_value_size(max_value_size_u32)
          .max_tx_size(max_tx_size_u32)
          .coins_per_utxo_word(coins_per_utxo_word)
          .prefer_pure_change(prefer_pure_change != 0)
      })
      .and_then(|tx_builder_config_builder| tx_builder_config_builder.rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderConfigBuilderBuild(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let rptr = ptr.rptr(&env)?;
    rptr
      .typed_ref::<TransactionBuilderConfigBuilder>()
      .and_then(|tx_builder_config_builder| tx_builder_config_builder.build().into_result())
      .and_then(|tx_builder_config| tx_builder_config.rptr().jptr(&env))
  })
  .jresult(&env)
}