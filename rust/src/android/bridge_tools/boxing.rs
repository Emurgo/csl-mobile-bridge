use crate::panic::{Result, ToResult};
use jni::objects::JObject;
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

pub trait PrimitiveTypeBoxing {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>>;
}

impl<T: PrimitiveTypeBoxing> PrimitiveTypeBoxing for Option<T> {
  fn jobject<'a>(self: Option<T>, env: &'a JNIEnv) -> Result<JObject<'a>> {
    match self {
      Some(value) => value.jobject(env),
      None => Ok(JObject::null()),
    }
  }
}

impl PrimitiveTypeBoxing for jint {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Integer")
      .and_then(|class| env.new_object(class, "(I)V", &[self.into()]))
      .into_result()
  }
}

impl PrimitiveTypeBoxing for jlong {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Long")
      .and_then(|class| env.new_object(class, "(J)V", &[self.into()]))
      .into_result()
  }
}

impl PrimitiveTypeBoxing for jboolean {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Boolean")
      .and_then(|class| env.new_object(class, "(Z)V", &[self.into()]))
      .into_result()
  }
}