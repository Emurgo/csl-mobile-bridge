use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jlong, jobject};
use jni::JNIEnv;
use std::convert::TryFrom;
use cardano_serialization_lib::tx_builder::{TransactionBuilder};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};
use cardano_serialization_lib::address::ByronAddress;
use cardano_serialization_lib::crypto::{Ed25519KeyHash};
use cardano_serialization_lib::{TransactionInput, TransactionOutput};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderAddKeyInput(
  env: JNIEnv, _: JObject, tx_builder: JRPtr, hash: JRPtr, input: JRPtr, amount: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_builder = tx_builder.rptr(&env)?;
    let hash = hash.rptr(&env)?;
    let input = input.rptr(&env)?;
    let amount = amount.rptr(&env)?;
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<Ed25519KeyHash>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Coin>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_key_input(hash, input, amount))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderAddBootstrapInput(
  env: JNIEnv, _: JObject, tx_builder: JRPtr, hash: JRPtr, input: JRPtr, amount: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_builder = tx_builder.rptr(&env)?;
    let hash = hash.rptr(&env)?;
    let input = input.rptr(&env)?;
    let amount = amount.rptr(&env)?;
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<ByronAddress>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Coin>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_bootstrap_input(hash, input, amount))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderAddOutput(
  env: JNIEnv, _: JObject, tx_builder: JRPtr, output: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_builder = tx_builder.rptr(&env)?;
    let output = output.rptr(&env)?;
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(output.typed_ref::<TransactionOutput>())
      .map(|(tx_builder, output)| tx_builder.add_output(output))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderSetFee(
  env: JNIEnv, _: JObject, tx_builder: JRPtr, fee: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_builder = tx_builder.rptr(&env)?;
    let fee = fee.rptr(&env)?;
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(fee.typed_ref::<Coin>())
      .map(|(tx_builder, fee)| tx_builder.set_fee(fee))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderSetTtl(
  env: JNIEnv, _: JObject, tx_builder: JRPtr, ttl: jlong
) -> jobject {
  handle_exception_result(|| {
    let tx_builder = tx_builder.rptr(&env)?;
    let ttl_u32 = u32::try_from(ttl).map_err(|err| err.to_string())?;
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .map(|tx_builder| tx_builder.set_ttl(ttl_u32))
  })
  .map(|_| JObject::null())
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_transactionBuilderNew(
  env: JNIEnv, _: JObject, linear_fee: JRPtr, minimum_utxo_val: JRPtr, pool_deposit: JRPtr, key_deposit: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let linear_fee = linear_fee.rptr(&env)?;
    let minimum_utxo_val = minimum_utxo_val.rptr(&env)?;
    let pool_deposit = pool_deposit.rptr(&env)?;
    let key_deposit = key_deposit.rptr(&env)?;
    linear_fee
      .typed_ref::<LinearFee>()
      .zip(minimum_utxo_val.typed_ref::<Coin>())
      .zip(pool_deposit.typed_ref::<BigNum>())
      .zip(key_deposit.typed_ref::<BigNum>())
      .map(|(((linear_fee, minimum_utxo_val), pool_deposit), key_deposit)| {
        TransactionBuilder::new(linear_fee, minimum_utxo_val, pool_deposit, key_deposit)
      })
      .and_then(|tx_builder| tx_builder.rptr().jptr(&env))
  })
  .jresult(&env)
}
