use cardano_serialization_lib::error::{DeserializeError};

pub trait ToFromBytes {
  fn to_bytes(&self) -> Vec<u8>;
  fn from_bytes(bytes: Vec<u8>) -> Result<Self, DeserializeError> where Self: Sized;
}
