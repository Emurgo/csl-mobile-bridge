use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use super::string::{CharPtr};
use crate::ptr::{RPtr};
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::crypto::{TransactionHash};

impl ToFromBytes for TransactionHash {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<TransactionHash, DeserializeError> {
    TransactionHash::from_bytes(bytes)
  }

}

#[no_mangle]
pub unsafe extern "C" fn transaction_hash_to_bytes(
  transaction_hash: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<TransactionHash>(transaction_hash, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn transaction_hash_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<TransactionHash>(data, len, result, error)
}
