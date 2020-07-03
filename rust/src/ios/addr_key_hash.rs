use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cddl_lib::crypto::{AddrKeyHash};

#[no_mangle]
pub unsafe extern "C" fn addr_key_hash_to_bytes(
  addr_key_hash: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| addr_key_hash.typed_ref::<AddrKeyHash>().map(|addr_key_hash| addr_key_hash.to_bytes()))
  .map(|bytes| bytes.into())
  .response(result, error)
}

// cddl_lib: from_bytes(bytes: Vec<u8>) -> Result<$name, JsValue>
// from react-native-chain-libs address.from_bytes(&[u8]) -> Result<Address, JsValue>
#[no_mangle]
pub unsafe extern "C" fn addr_key_hash_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    AddrKeyHash::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|addr_key_hash| addr_key_hash.rptr())
  .response(result, error)
}
