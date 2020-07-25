use super::data::DataPtr;
use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::crypto::{Ed25519KeyHash};

#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_to_bytes(
  ed25519_key_hash: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    ed25519_key_hash.typed_ref::<Ed25519KeyHash>().map(|ed25519_key_hash| ed25519_key_hash.to_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

// cardano_serialization_lib: from_bytes(bytes: Vec<u8>) -> Result<$name, JsValue>
// from react-native-chain-libs address.from_bytes(&[u8]) -> Result<Address, JsValue>
#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    Ed25519KeyHash::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|ed25519_key_hash| ed25519_key_hash.rptr())
  .response(result, error)
}
