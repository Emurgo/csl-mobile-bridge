use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub type CharPtr = *const c_char;

pub trait IntoStr<T> {
  fn into_str(&self) -> T;
}

pub trait IntoCString {
  fn into_cstr(&self) -> CharPtr;
}

pub trait IntoOptionalCString {
  fn into_opt_cstr(&self) -> Option<CharPtr>;
}

impl IntoStr<& str> for CharPtr<> {
  fn into_str(& self) -> & str {
    unsafe { CStr::from_ptr(*self).to_str().unwrap() }
  }
}

impl IntoStr<String> for CharPtr {
  fn into_str(&self) -> String {
    unsafe { CStr::from_ptr(*self).to_str().unwrap().to_string() }
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

impl IntoOptionalCString for Option<&str> {
  fn into_opt_cstr(&self) -> Option<CharPtr> {
    match self {
      Some(value) => Some(value.into_cstr()),
      None => None,
    }
  }
}

#[no_mangle]
pub unsafe extern "C" fn charptr_free(ptr: &mut CharPtr) {
  let _ = CString::from_raw(*ptr as *mut c_char);
  *ptr = std::ptr::null_mut();
}
