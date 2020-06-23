use crate::ptr::RPtr;

#[no_mangle]
pub extern "C" fn rptr_from_usize(usz: usize) -> RPtr {
  usz.into()
}

#[no_mangle]
pub extern "C" fn rptr_into_usize(ptr: RPtr) -> usize {
  ptr.into()
}

#[no_mangle]
pub unsafe extern "C" fn rptr_free(ptr: &mut RPtr) {
  ptr.free();
}
