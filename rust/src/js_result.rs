use crate::panic::{Result, ToResult};
use wasm_bindgen::JsValue;
use cardano_serialization_lib::error::{DeserializeError};

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
