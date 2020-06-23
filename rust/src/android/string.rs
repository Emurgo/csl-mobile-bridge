use crate::panic::{Result, ToResult};
use jni::objects::JString;
use jni::JNIEnv;

pub trait ToJniString {
  fn jstring<'a>(self, env: &'a JNIEnv) -> Result<JString<'a>>;
}

pub trait ToString {
  fn string(self, env: &JNIEnv) -> Result<String>;
}

impl<'a> ToString for JString<'a> {
  fn string(self, env: &JNIEnv) -> Result<String> {
    env.get_string(self).map(|res| res.into()).into_result()
  }
}

impl ToJniString for &str {
  fn jstring<'a>(self, env: &'a JNIEnv) -> Result<JString<'a>> {
    env.new_string(self).into_result()
  }
}

impl ToJniString for String {
  fn jstring<'a>(self, env: &'a JNIEnv) -> Result<JString<'a>> {
    env.new_string(self).into_result()
  }
}
