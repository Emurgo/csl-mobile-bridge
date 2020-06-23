use crate::panic::{Result, ToResult};
use std::any::Any;
use std::ffi::c_void;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct RPtr(*mut c_void);

impl From<RPtr> for usize {
  fn from(ptr: RPtr) -> Self {
    ptr.0 as usize
  }
}

impl From<usize> for RPtr {
  fn from(ptr: usize) -> Self {
    Self(ptr as *mut c_void)
  }
}

pub trait RPtrRepresentable: Sized + 'static {
  fn rptr(self) -> RPtr {
    let b: Box<Box<dyn Any>> = Box::new(Box::new(self));
    RPtr(Box::into_raw(b) as *mut c_void)
  }
}

impl RPtr {
  pub fn new<T: RPtrRepresentable>(val: T) -> Self {
    val.rptr()
  }

  pub unsafe fn typed_ref<T: RPtrRepresentable>(&self) -> Result<&mut T> {
    if self.0.is_null() {
      return Err(String::from("Pointer is NULL"));
    }
    (self.0 as *mut Box<dyn Any>)
      .as_mut()
      .and_then(|any| any.downcast_mut::<T>())
      .ok_or_else(|| format!("Bad pointer: 0x{:x}", self.0 as usize))
  }

  pub unsafe fn owned<T: RPtrRepresentable>(mut self) -> Result<T> {
    if self.0.is_null() {
      return Err(String::from("Pointer is NULL"));
    }
    let boxed = *Box::from_raw(self.0 as *mut Box<dyn Any>);
    self.0 = std::ptr::null_mut();
    boxed.downcast::<T>().into_result().map(|boxed| *boxed)
  }

  pub unsafe fn free(&mut self) {
    if self.0.is_null() {
      return;
    }
    let _ = Box::from_raw(self.0 as *mut Box<dyn Any>);
    self.0 = std::ptr::null_mut();
  }
}

impl<T: RPtrRepresentable> RPtrRepresentable for Option<T> {
  fn rptr(self) -> RPtr {
    match self {
      Some(val) => val.rptr(),
      None => RPtr(std::ptr::null_mut())
    }
  }
}
