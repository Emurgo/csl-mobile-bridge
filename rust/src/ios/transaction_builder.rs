use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, Zip, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::tx_builder::{TransactionBuilder, TransactionBuilderConfig};
use cardano_serialization_lib::metadata::{AuxiliaryData};
use cardano_serialization_lib::utils::{Coin, Value};
use cardano_serialization_lib::crypto::{Ed25519KeyHash, ScriptHash};
use cardano_serialization_lib::address::{Address, ByronAddress};
use cardano_serialization_lib::{TransactionInput, TransactionOutput, Certificates, Withdrawals};

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_key_input(
  tx_builder: RPtr, hash: RPtr, input: RPtr, amount: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<Ed25519KeyHash>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Value>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_key_input(hash, input, amount))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_script_input(
  tx_builder: RPtr, hash: RPtr, input: RPtr, amount: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(hash.typed_ref::<ScriptHash>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Value>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_script_input(hash, input, amount))
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
      .zip(amount.typed_ref::<Value>())
      .map(|(((tx_builder, hash), input), amount)| tx_builder.add_bootstrap_input(hash, input, amount))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_input(
  tx_builder: RPtr, address: RPtr, input: RPtr, amount: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(address.typed_ref::<Address>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Value>())
      .map(|(((tx_builder, address), input), amount)| tx_builder.add_input(address, input, amount))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_fee_for_input(
  tx_builder: RPtr, address: RPtr, input: RPtr, amount: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(address.typed_ref::<Address>())
      .zip(input.typed_ref::<TransactionInput>())
      .zip(amount.typed_ref::<Value>())
      .and_then(|(((tx_builder, address), input), amount)| tx_builder.fee_for_input(address, input, amount).into_result())
  })
  .map(|fee| fee.rptr())
  .response(result, error)
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
pub unsafe extern "C" fn transaction_builder_fee_for_output(
  rptr: RPtr, output: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .zip(output.typed_ref::<TransactionOutput>())
      .and_then(|(tx_builder, output)| tx_builder.fee_for_output(output).into_result())
    })
    .map(|fee| fee.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_fee(
  tx_builder: RPtr, fee: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(fee.typed_ref::<Coin>())
      .map(|(tx_builder, fee)| tx_builder.set_fee(fee))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_ttl(
  tx_builder: RPtr, ttl: u32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .map(|tx_builder| tx_builder.set_ttl(ttl))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_validity_start_interval(
  tx_builder: RPtr, vst: u32, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .map(|tx_builder| tx_builder.set_validity_start_interval(vst))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_certs(
  tx_builder: RPtr, certs: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(certs.typed_ref::<Certificates>())
      .map(|(tx_builder, certs)| tx_builder.set_certs(certs))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_withdrawals(
  tx_builder: RPtr, withdrawals: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(withdrawals.typed_ref::<Withdrawals>())
      .map(|(tx_builder, withdrawals)| tx_builder.set_withdrawals(withdrawals))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_auxiliary_data(
  tx_builder: RPtr, auxiliary_data: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_builder
      .typed_ref::<TransactionBuilder>()
      .zip(auxiliary_data.typed_ref::<AuxiliaryData>())
      .map(|(tx_builder, auxiliary_data)| tx_builder.set_auxiliary_data(auxiliary_data))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_new(
  config: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    config
      .typed_ref::<TransactionBuilderConfig>()
      .map(|config| TransactionBuilder::new(config))
    })
    .map(|tx_builder| tx_builder.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_explicit_input(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.get_explicit_input().into_result())
    })
    .map(|amount| amount.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_implicit_input(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.get_implicit_input().into_result())
    })
    .map(|amount| amount.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_explicit_output(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.get_explicit_output().into_result())
    })
    .map(|amount| amount.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_deposit(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.get_deposit().into_result())
    })
    .map(|deposit| deposit.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_fee_if_set(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .map(|tx_builder| tx_builder.get_fee_if_set())
    })
    .map(|amount| amount.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_change_if_needed(
  rptr: RPtr, address: RPtr, result: &mut bool, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .zip(address.typed_ref::<Address>())
      .and_then(|(tx_builder, address)| tx_builder.add_change_if_needed(address).into_result())
    })
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_build(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.build().into_result())
    })
    .map(|tx_body| tx_body.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_builder_min_fee(
  rptr: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    rptr
      .typed_ref::<TransactionBuilder>()
      .and_then(|tx_builder| tx_builder.min_fee().into_result())
    })
    .map(|fee| fee.rptr())
    .response(result, error)
}
