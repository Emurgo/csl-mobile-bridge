use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{EnterpriseAddress, StakeCredential};

#[no_mangle]
pub unsafe extern "C" fn enterprise_address_new(
  network: u8, payment: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    payment
      .typed_ref::<StakeCredential>()
      .map(|payment| EnterpriseAddress::new(network, payment))
    })
    .map(|reward_address| reward_address.rptr())
    .response(result, error)
}
