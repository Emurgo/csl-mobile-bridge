#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataPtr {
  ptr: *const u8,
  len: usize
}

impl DataPtr {
  pub unsafe fn rust_ref(&self) -> &[u8] {
    std::slice::from_raw_parts(self.ptr, self.len)
  }

  pub unsafe fn free(&mut self) {
    if self.ptr.is_null() {
      return;
    }
    let _ = Vec::from_raw_parts(self.ptr as *mut u8, self.len, self.len);
    self.ptr = std::ptr::null();
  }
}

impl From<&[u8]> for DataPtr {
  fn from(data: &[u8]) -> Self {
    Vec::from(data).into()
  }
}

impl From<Vec<u8>> for DataPtr {
  fn from(data: Vec<u8>) -> Self {
    let len = data.len();
    let mut slice = data.into_boxed_slice();
    let out = slice.as_mut_ptr();
    std::mem::forget(slice);
    Self { ptr: out, len: len }
  }
}

#[no_mangle]
pub unsafe extern "C" fn dataptr_free(data: &mut DataPtr) {
  data.free();
}
