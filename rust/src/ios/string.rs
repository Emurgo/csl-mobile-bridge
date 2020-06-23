use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub type CharPtr = *const c_char;

pub trait IntoStr {
  fn into_str(&self) -> &str;
}

pub trait IntoCString {
  fn into_cstr(&self) -> CharPtr;
}

impl IntoStr for CharPtr {
  fn into_str(&self) -> &str {
    unsafe { CStr::from_ptr(*self).to_str().unwrap() }
  }
}

impl IntoCString for &str {
  fn into_cstr(&self) -> CharPtr {
    CString::new(self.as_bytes()).unwrap().into_raw()
  }
}

impl IntoCString for String {
  fn into_cstr(&self) -> CharPtr {
    CString::new(self.as_bytes()).unwrap().into_raw()
  }
}

#[no_mangle]
pub unsafe extern "C" fn charptr_free(ptr: &mut CharPtr) {
  let _ = CString::from_raw(*ptr as *mut c_char);
  *ptr = std::ptr::null_mut();
}
