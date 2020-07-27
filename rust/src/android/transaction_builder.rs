use super::primitive::ToPrimitiveObject;
use super::ptr_j::*;
use super::result::ToJniResult;
use crate::panic::{handle_exception_result, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::JObject;
use jni::sys::{jlong, jobject};
use jni::JNIEnv;
use cardano_serialization_lib::tx_builder::{TransactionBuilder};
use cardano_serialization_lib::crypto::{Vkeywitness, Vkeywitnesses};
use cardano_serialization_lib::fees::{LinearFee};
use cardano_serialization_lib::utils::{Coin, BigNum};

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
