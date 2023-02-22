use crate::panic::{Result, ToResult};
use jni::objects::JObject;
use jni::sys::{jlong, jint, jbyte, jboolean};
use jni::JNIEnv;

pub trait PrimitiveTypeUnboxing<T> {
  fn unbox(self, env: &JNIEnv) -> Result<Option<T>>;
}

impl PrimitiveTypeUnboxing<jint> for JObject<'_> {
  fn unbox(self, env: &JNIEnv) -> Result<Option<jint>> {
    if self.is_null() {
      Ok(None)
    } else {
      let value = env.call_method(self, "intValue", "()I", &[])
          .expect("JNIEnv#call_method should return JValue")
          .i().into_result()?;
      Ok(Some(value))
    }
  }
}

impl PrimitiveTypeUnboxing<jlong> for JObject<'_> {
  fn unbox(self, env: &JNIEnv) -> Result<Option<jlong>> {
    if self.is_null() {
      Ok(None)
    } else {
      let value = env.call_method(self, "longValue", "()J", &[])
          .expect("JNIEnv#call_method should return JValue")
          .j().into_result()?;
      Ok(Some(value))
    }
  }
}

impl PrimitiveTypeUnboxing<jboolean> for JObject<'_> {
  fn unbox(self, env: &JNIEnv) -> Result<Option<jboolean>> {
    if self.is_null() {
      Ok(None)
    } else {
      let value = env.call_method(self, "booleanValue", "()Z", &[])
          .expect("JNIEnv#call_method should return JValue")
          .z().into_result()?;
      Ok(Some(value as jboolean))
    }
  }
}

impl PrimitiveTypeUnboxing<jbyte> for JObject<'_> {
  fn unbox(self, env: &JNIEnv) -> Result<Option<jbyte>> {
    if self.is_null() {
      Ok(None)
    } else {
      let value = env.call_method(self, "byteValue", "()B", &[])
          .expect("JNIEnv#call_method should return JValue")
          .b().into_result()?;
      Ok(Some(value))
    }
  }
}


