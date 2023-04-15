pub mod bridge;
mod bridge_tools;
// mod transaction;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_cslmobilebridge_Native_initLibrary(
  _env: jni::JNIEnv, _: jni::objects::JObject
) {
  crate::panic::hide_exceptions();
}
