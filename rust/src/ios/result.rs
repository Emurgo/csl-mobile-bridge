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

impl CResult<i32> for Result<Option<i32>> {
  fn response(&self, val: &mut i32, error: &mut CharPtr) -> bool {
    match self {
      Err(err) => {
        *error = err.into_cstr();
        false
      }
      Ok(value) => {
        match value {
          Some(value) => {
            *val = *value;
            true
          }
          None => {
            false
          }
        }
      }
    }
  }
}
