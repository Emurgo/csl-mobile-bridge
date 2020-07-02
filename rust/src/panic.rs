use std::any::Any;
use std::panic;

pub type Result<T> = std::result::Result<T, String>;

pub trait ToResult<T> {
  fn into_result(self) -> Result<T>;
}

pub trait Zip<T1> {
  fn zip<T2>(self, other: Result<T2>) -> Result<(T1, T2)>;
}

impl<T1> Zip<T1> for Result<T1> {
  fn zip<T2>(self, other: Result<T2>) -> Result<(T1, T2)> {
    self.and_then(|val1| other.map(|val2| (val1, val2)))
  }
}

fn string_from_any_err(err: Box<dyn Any>) -> String {
  if let Some(string) = err.downcast_ref::<String>() {
    string.clone()
  } else if let Some(string) = err.downcast_ref::<&'static str>() {
    String::from(*string)
  } else {
    format!("Reason: {:?}", err)
  }
}

impl<T> ToResult<T> for std::result::Result<T, Box<dyn Any + Send + 'static>> {
  fn into_result(self) -> Result<T> {
    self.map_err(|err| string_from_any_err(err))
  }
}

impl<T> ToResult<T> for std::result::Result<T, Box<dyn Any + 'static>> {
  fn into_result(self) -> Result<T> {
    self.map_err(string_from_any_err)
  }
}

#[allow(dead_code)]
pub fn handle_exception<F: FnOnce() -> R + panic::UnwindSafe, R>(func: F) -> Result<R> {
  handle_exception_result(|| Ok(func()))
}

pub fn handle_exception_result<F: FnOnce() -> Result<R> + panic::UnwindSafe, R>(
  func: F
) -> Result<R> {
  panic::catch_unwind(func).into_result().and_then(|res| res)
}

#[allow(dead_code)]
pub fn hide_exceptions() {
  panic::set_hook(Box::new(|_| {}));
}
