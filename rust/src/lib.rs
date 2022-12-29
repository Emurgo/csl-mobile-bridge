extern crate cardano_serialization_lib;

mod js_result;
mod panic;
mod ptr;
mod ptr_impl;
mod utils;
mod enum_maps;

pub use ptr::*;

#[cfg(target_os = "android")]
extern crate jni;
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use self::android::*;

#[cfg(target_os = "ios")]
mod ios;
pub mod arrays;

#[cfg(target_os = "ios")]
pub use self::ios::*;
