use jni::objects::{JObject, JString};
use jni::sys::jlong;
use jni::JNIEnv;

use std::mem;

use super::string::ToString;
use super::primitives::*;
use crate::panic::{Result, ToResult};
use crate::ptr::{RPtr, RPtrRepresentable};

pub type JRPtr<'a> = JObject<'a>;

pub struct RPtrRef(RPtr);

impl RPtrRef {
  pub unsafe fn typed_ref<T: RPtrRepresentable>(&self) -> Result<&mut T> {
    self.0.typed_ref::<T>()
  }

  pub unsafe fn option_typed_ref<T: RPtrRepresentable>(&self) -> Result<Option<&mut T>> {
    self.0.option_typed_ref::<T>()
  }

  pub unsafe fn owned<T: RPtrRepresentable>(self) -> Result<T> {
    self.0.owned::<T>()
  }

  fn new(ptr: RPtr) -> Self {
    return Self(ptr);
  }

  fn to_ptr(self) -> RPtr {
    self.0
  }
}

pub trait ToJniPtr {
  fn jptr<'a>(self, env: &'a JNIEnv) -> Result<JRPtr<'a>>;
}

pub trait FromJniPtr {
  fn rptr<'a>(self, env: &'a JNIEnv) -> Result<RPtrRef>;
  unsafe fn owned<'a, T: RPtrRepresentable>(self, env: &'a JNIEnv) -> Result<T>;
  unsafe fn free<'a>(self, env: &'a JNIEnv) -> Result<()>;
}



impl<'a> FromJniPtr for JRPtr<'a> {
  fn rptr(self, env: &JNIEnv) -> Result<RPtrRef> {
    let class_obj = env
      .call_method(self, "getClass", "()Ljava/lang/Class;", &[])
      .and_then(|res| res.l())
      .into_result()?;
    let name = env
      .call_method(class_obj, "getSimpleName", "()Ljava/lang/String;", &[])
      .and_then(|res| res.l())
      .into_result()
      .and_then(|obj| JString::from(obj).string(env))?;
    if name != "RPtr" {
      return Err(format!("Wrong class: {}, expected RPtr", name));
    }
    env
      .get_field(self, "ptr", "J")
      .and_then(|res| res.j())
      .map(|iptr| RPtrRef::new(usize::from_jlong(iptr).into()))
      .into_result()
  }

  unsafe fn owned<T: RPtrRepresentable>(self, env: &JNIEnv) -> Result<T> {
    self
      .rptr(env)
      .and_then(|rptr| rptr.to_ptr().owned::<T>())
      .and_then(|val| env.set_field(self, "ptr", "J", 0i64.into()).map(|_| val).into_result())
  }

  unsafe fn free(self, env: &JNIEnv) -> Result<()> {
    self.rptr(env).and_then(|rptr| {
      env.set_field(self, "ptr", "J", 0i64.into()).into_result().map(|_| rptr.to_ptr().free())
    })
  }
}

impl ToJniPtr for RPtr {
  fn jptr<'a>(self, env: &'a JNIEnv) -> Result<JRPtr<'a>> {
    let ptr: usize = self.into();
    env
      .find_class("io/emurgo/cslmobilebridge/RPtr")
      .and_then(|class| env.new_object(class, "(J)V", &[ptr.into_jlong().into()]))
      .into_result()
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_ptrFree(
  env: JNIEnv, _: JObject, ptr: JRPtr
) {
  ptr.free(&env).unwrap();
}

pub fn clone_optional<T: Clone>(optional_ref: Option<&mut T>) -> Option<T> where T: Clone {
  match optional_ref {
    Some(val) => Some(val.clone()),
    None => None
  }
}
