use super::string::*;
use crate::panic::Result;

pub trait CResult<T> {
  fn response(&self, val: &mut T, error: &mut CharPtr) -> bool;
}

impl<T: Copy> CResult<T> for Result<T> {
  fn response(&self, val: &mut T, error: &mut CharPtr) -> bool {
    match self {
      Err(err) => {
        *error = err.into_cstr();
        false
      }
      Ok(value) => {
        *val = *value;
        true
      }
    }
  }
}
