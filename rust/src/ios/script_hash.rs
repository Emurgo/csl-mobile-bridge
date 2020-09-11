use super::string::{CharPtr};
use crate::ptr::{RPtr};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::crypto::{ScriptHash};

impl ToFromBytes for ScriptHash {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<ScriptHash, DeserializeError> {
    ScriptHash::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn script_hash_to_bytes(
  script_hash: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<ScriptHash>(script_hash, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn script_hash_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<ScriptHash>(data, len, result, error)
}
