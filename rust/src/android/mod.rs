mod address;
mod primitive;
mod ptr_j;
mod result;
mod string;
mod addr_key_hash;
// declare other modules here
// mod transaction;


pub use address::*;
pub use addr_key_hash::*;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_initLibrary(
  _env: jni::JNIEnv, _: jni::objects::JObject
) {
  crate::panic::hide_exceptions();
}
