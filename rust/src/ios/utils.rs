use super::data::DataPtr;
use super::result::CResult;
use super::string::*;
use crate::utils::ToFromBytes;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};

pub unsafe fn to_bytes<T: RPtrRepresentable + ToFromBytes>(
  obj: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    obj.typed_ref::<T>().map(|obj| obj.to_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

pub unsafe fn from_bytes<T: RPtrRepresentable + ToFromBytes>(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    T::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|obj| obj.rptr())
  .response(result, error)
}
