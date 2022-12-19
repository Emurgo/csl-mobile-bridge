use jni::objects::JObject;
use jni::sys::jobject;
use jni::JNIEnv;

use super::string::ToJniString;
use crate::panic::{Result, ToResult};

pub trait ToJniResult {
  fn jresult<'a>(self, env: &'a JNIEnv) -> jobject;
}

impl<T> ToResult<T> for std::result::Result<T, jni::errors::Error> {
  fn into_result(self) -> Result<T> {
    self.map_err(|err| format!("{}", err))
  }
}

impl<'a, T> ToJniResult for Result<T>
where
  T: Into<JObject<'a>>
{
  fn jresult(self, env: &JNIEnv) -> jobject {
    static CONSTRUCTOR: &str = "(Ljava/lang/Object;Ljava/lang/String;)V";

    let class = env.find_class("io/emurgo/rnhaskellshelley/Result").expect("Can't find Result class");
    match self {
      Ok(res) => {
        let jobj = res.into();
        env
          .new_object(class, CONSTRUCTOR, &[jobj.into(), JObject::null().into()])
          .unwrap()
          .into_raw()
      }
      Err(error) => {
        let jstr = *error.jstring(env).expect("Couldn't create java string!");
        env
          .new_object(class, CONSTRUCTOR, &[JObject::null().into(), jstr.into()])
          .unwrap()
          .into_raw()
      }
    }
  }
}
