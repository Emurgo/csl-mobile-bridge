use crate::panic::{Result, ToResult};
use wasm_bindgen::JsValue;

impl<T> ToResult<T> for std::result::Result<T, JsValue> {
  fn into_result(self) -> Result<T> {
    self.map_err(|jsval| format!("{:?}", jsval))
  }
}
