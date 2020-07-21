mod address;
mod primitive;
mod ptr_j;
mod hash_type;
mod result;
mod string;
mod big_num;
mod ed25519_key_hash;
mod transaction_hash;
mod stake_credential;
mod base_address;
mod unit_interval;
mod transaction_input;
mod transaction_output;
// declare other modules here
// mod transaction;

pub use address::*;
pub use stake_credential::*;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_initLibrary(
  _env: jni::JNIEnv, _: jni::objects::JObject
) {
  crate::panic::hide_exceptions();
}
