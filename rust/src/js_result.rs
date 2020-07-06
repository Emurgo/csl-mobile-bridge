use crate::panic::{Result, ToResult};
use wasm_bindgen::JsValue;
use cddl_lib::prelude::{DeserializeError};

impl<T> ToResult<T> for std::result::Result<T, JsValue> {
  fn into_result(self) -> Result<T> {
    self.map_err(|jsval| format!("{:?}", jsval))
  }
}

impl<T> ToResult<T> for std::result::Result<T, DeserializeError> {
  fn into_result(self) -> Result<T> {
    self.map_err(|e| e.to_string())
  }
}
