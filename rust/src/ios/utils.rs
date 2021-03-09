use super::data::DataPtr;
use super::result::CResult;
use super::string::*;
use crate::utils::ToFromBytes;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};

use cardano_serialization_lib::utils::{
  hash_transaction,
  make_vkey_witness,
  make_icarus_bootstrap_witness,
  min_ada_required,
  Value,
  BigNum
};
use cardano_serialization_lib::{TransactionBody};
use cardano_serialization_lib::crypto::{Bip32PrivateKey, PrivateKey, TransactionHash};
use cardano_serialization_lib::address::ByronAddress;
use cardano_serialization_lib::metadata::{
  TransactionMetadatum,
  MetadataJsonSchema,
  encode_json_str_to_metadatum,
  decode_metadatum_to_json_str
};

pub unsafe fn to_bytes<T: RPtrRepresentable + ToFromBytes>(
  obj: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    obj.typed_ref::<T>().map(|obj| obj.to_bytes())
  })
  .map(|bytes| bytes.into())
  .response(result, error)
}

pub unsafe fn from_bytes<T: RPtrRepresentable + ToFromBytes>(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    T::from_bytes(std::slice::from_raw_parts(data, len).into()).into_result()
  })
  .map(|obj| obj.rptr())
  .response(result, error)
}

// utils from cardano_serialization_lib::utils

#[no_mangle]
pub unsafe extern "C" fn utils_make_icarus_bootstrap_witness(
  tx_body_hash: RPtr, addr: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_body_hash.typed_ref::<TransactionHash>()
      .zip(addr.typed_ref::<ByronAddress>())
      .zip(key.typed_ref::<Bip32PrivateKey>())
      .map(|((tx_body_hash, addr), key)| {
        make_icarus_bootstrap_witness(tx_body_hash, addr, key)
      })
    })
    .map(|witness| witness.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn utils_make_vkey_witness(
  tx_body_hash: RPtr, sk: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_body_hash.typed_ref::<TransactionHash>()
      .zip(sk.typed_ref::<PrivateKey>())
      .map(|(tx_body_hash, sk)| {
        make_vkey_witness(tx_body_hash, sk)
      })
    })
    .map(|witness| witness.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn utils_hash_transaction(
  tx_body: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    tx_body.typed_ref::<TransactionBody>()
      .map(|tx_body| {
        hash_transaction(tx_body)
      })
    })
    .map(|hash| hash.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn utils_min_ada_required(
  assets: RPtr, min_utxo_val: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    assets.typed_ref::<Value>()
      .zip(min_utxo_val.typed_ref::<BigNum>())
      .map(|(assets, min_utxo_val)| {
        min_ada_required(assets, min_utxo_val)
      })
    })
    .map(|min_ada| min_ada.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn utils_encode_json_str_to_metadatum(
  json: CharPtr, schema: i32, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {

    let schema_enum: MetadataJsonSchema;
    match schema {
      0 => schema_enum = MetadataJsonSchema::NoConversions,
      1 => schema_enum = MetadataJsonSchema::BasicConversions,
      2 => schema_enum = MetadataJsonSchema::DetailedSchema,
      _ => schema_enum = MetadataJsonSchema::BasicConversions,
    }
    encode_json_str_to_metadatum(json.into_str().to_string(), schema_enum)
      .into_result()
      .map(|tx_metadatum| tx_metadatum.rptr())
  })
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn utils_decode_metadatum_to_json_str(
  metadatum: RPtr, schema: i32, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {

    let schema_enum: MetadataJsonSchema;
    match schema {
      0 => schema_enum = MetadataJsonSchema::NoConversions,
      1 => schema_enum = MetadataJsonSchema::BasicConversions,
      2 => schema_enum = MetadataJsonSchema::DetailedSchema,
      _ => schema_enum = MetadataJsonSchema::BasicConversions,
    }
    metadatum.typed_ref::<TransactionMetadatum>()
      .and_then(|metadatum| {
        decode_metadatum_to_json_str(metadatum, schema_enum).into_result()
      })
      .map(|string| string.into_cstr())
  })
  .response(result, error)
}
