use jni::sys::jlong;
use jni::sys::jboolean;
use std::mem;
use crate::panic::Result;

pub trait JLongConvertible {
    fn try_from_jlong(value: jlong) -> Result<Self> where Self: Sized;
    fn from_jlong(long: jlong) -> Self;
    fn into_jlong(self) -> jlong;
}

pub trait JLongOptionConvertible {
    fn try_from_jlong(value: Option<jlong>) -> Result<Self> where Self: Sized;
    fn into_jlong(self) -> Option<jlong>;
    fn from_jlong(long: jlong) -> Self;
}

impl<T: JLongConvertible> JLongOptionConvertible for Option<T> {

    fn try_from_jlong(value: Option<jlong>) -> Result<Self> {
        match value {
            Some(value) => Ok(Some(T::try_from_jlong(value)?)),
            None => Ok(None)
        }
    }

    fn into_jlong(self: Option<T>) -> Option<jlong> {
        match self {
            Some(value) => Some(value.into_jlong()),
            None => None,
        }
    }

    fn from_jlong(long: jlong) -> Self {
        Some(T::from_jlong(long))
    }
}

impl JLongConvertible for usize {

    fn try_from_jlong(value: jlong) -> Result<Self> {
        Ok(Self::from_jlong(value))
    }

    fn from_jlong(long: jlong) -> Self {
        #[cfg(target_pointer_width = "32")]
        {
            long as usize
        }
        #[cfg(target_pointer_width = "64")]
        {
            u64::from_jlong(long) as usize
        }
    }

    fn into_jlong(self) -> jlong {
        #[cfg(target_pointer_width = "32")]
        {
            self as jlong
        }
        #[cfg(target_pointer_width = "64")]
        {
            (self as u64).into_jlong()
        }
    }
}

impl JLongConvertible for u64 {

    fn try_from_jlong(long: jlong) -> Result<Self> {
        Ok(Self::from_jlong(long))
    }

    fn from_jlong(long: jlong) -> Self {
        unsafe { mem::transmute::<jlong, u64>(long) }
    }

    fn into_jlong(self) -> jlong {
        unsafe { mem::transmute::<u64, jlong>(self) }
    }
}

impl JLongConvertible for i64 {
    fn try_from_jlong(long: jlong) -> Result<Self> {
        Ok(Self::from_jlong(long))
    }

    fn from_jlong(long: jlong) -> Self {
        unsafe { mem::transmute::<jlong, i64>(long) }
    }

    fn into_jlong(self) -> jlong {
        unsafe { mem::transmute::<i64, jlong>(self) }
    }
}

macro_rules! jlong_from_to {
    ($primitive_type:ty) => {
        impl JLongConvertible for $primitive_type {
                fn try_from_jlong(long: jlong) -> Result<Self> {
                  if long > <$primitive_type>::MAX.into_jlong() || long < <$primitive_type>::MIN.into_jlong() {
                    return Err("Input value out of range".into());
                  } else {
                    Ok(Self::from_jlong(long))
                  }
                }

                fn from_jlong(long: jlong) -> Self {
                    long as Self
                }

                fn into_jlong(self) -> jlong {
                    self as jlong
                }
        }
    };
}

jlong_from_to!(u8);
jlong_from_to!(i8);
jlong_from_to!(u16);
jlong_from_to!(i16);
jlong_from_to!(u32);
jlong_from_to!(i32);

pub trait IntoBool {
    fn into_bool(self) -> bool;
}

impl IntoBool for jboolean {
    fn into_bool(self) -> bool {
        self != 0
    }
}