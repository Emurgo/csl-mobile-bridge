use crate::panic::{Result, ToResult};
use jni::objects::JObject;
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

pub trait ToPrimitiveObject {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>>;
}

impl ToPrimitiveObject for jint {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Integer")
      .and_then(|class| env.new_object(class, "(I)V", &[self.into()]))
      .into_result()
  }
}

impl ToPrimitiveObject for jlong {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Long")
      .and_then(|class| env.new_object(class, "(J)V", &[self.into()]))
      .into_result()
  }
}

impl ToPrimitiveObject for jboolean {
  fn jobject<'a>(self, env: &'a JNIEnv) -> Result<JObject<'a>> {
    env
      .find_class("java/lang/Boolean")
      .and_then(|class| env.new_object(class, "(Z)V", &[self.into()]))
      .into_result()
  }
}
