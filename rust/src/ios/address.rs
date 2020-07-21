// NOTE: currently the Address structure is not supported for
// non-wasm targets

use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::address::{Address};

// cardano_serialization_lib: (&self) -> Vec<u8>
// from react-native-chain-libs address.as_bytes -> Vec<u8>
#[no_mangle]
pub unsafe extern "C" fn address_to_bytes(
  address: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| address.typed_ref::<Address>().map(|address| address.to_bytes()))
  .map(|bytes| bytes.into())
  .response(result, error)
}

// cardano_serialization_lib: Address.from_bytes(Vec<u8>) -> Result<Address, JsValue>
// from react-native-chain-libs address.from_bytes(&[u8]) -> Result<Address, JsValue>
#[no_mangle]
pub unsafe extern "C" fn address_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Address::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|address| address.rptr())
  .response(result, error)
}
