use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::crypto::{ScriptHash};
use cardano_serialization_lib::{ScriptHashes};

impl ToFromBytes for ScriptHashes {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<ScriptHashes, DeserializeError> {
    ScriptHashes::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn script_hashes_to_bytes(
  script_hashes: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<ScriptHashes>(script_hashes, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn script_hashes_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<ScriptHashes>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn script_hashes_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| ScriptHashes::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn script_hashes_len(
  script_hashes: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| script_hashes.typed_ref::<ScriptHashes>().map(|script_hashes| script_hashes.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn script_hashes_get(
  script_hashes: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    script_hashes.typed_ref::<ScriptHashes>().map(|script_hashes| script_hashes.get(index))
  })
  .map(|script_hash| script_hash.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn script_hashes_add(
  script_hashes: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    script_hashes
      .typed_ref::<ScriptHashes>()
      .zip(item.typed_ref::<ScriptHash>())
      .map(|(script_hashes, item)| script_hashes.add(item))
  })
  .response(&mut (), error)
}
