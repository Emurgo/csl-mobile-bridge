use super::result::CResult;
use super::string::CharPtr;
use crate::panic::{handle_exception, handle_exception_result, Zip};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::{Certificate, Certificates};

impl ToFromBytes for Certificates {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Certificates, DeserializeError> {
    Certificates::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn certificates_to_bytes(
  certificates: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<Certificates>(certificates, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificates_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<Certificates>(data, len, result, error)
}

#[no_mangle]
pub extern "C" fn certificates_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception(|| Certificates::new().rptr()).response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificates_len(
  certificates: RPtr, result: &mut usize, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| certificates.typed_ref::<Certificates>().map(|certs| certs.len()))
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificates_get(
  certificates: RPtr, index: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    certificates.typed_ref::<Certificates>().map(|certificates| certificates.get(index))
  })
  .map(|certificate| certificate.rptr())
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn certificates_add(
  certificates: &mut RPtr, item: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    certificates
      .typed_ref::<Certificates>()
      .zip(item.typed_ref::<Certificate>())
      .map(|(certificates, item)| certificates.add(item))
  })
  .response(&mut (), error)
}
