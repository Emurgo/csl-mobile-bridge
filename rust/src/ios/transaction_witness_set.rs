use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::TransactionWitnessSet;
use cardano_serialization_lib::crypto::{BootstrapWitnesses, Vkeywitnesses};

#[no_mangle]
pub extern "C" fn transaction_witness_set_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| TransactionWitnessSet::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_vkeys(
  transaction_witness_set: RPtr, vkeywitnesses: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_witness_set
      .typed_ref::<TransactionWitnessSet>()
      .zip(vkeywitnesses.typed_ref::<Vkeywitnesses>())
      .map(|(witness_set, witnesses)| witness_set.set_vkeys(witnesses))
  })
  .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_bootstraps(
  transaction_witness_set: RPtr, bootstrap_witnesses: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    transaction_witness_set
      .typed_ref::<TransactionWitnessSet>()
      .zip(bootstrap_witnesses.typed_ref::<BootstrapWitnesses>())
      .map(|(witness_set, witnesses)| witness_set.set_bootstraps(witnesses))
  })
  .response(&mut (), error)
}
