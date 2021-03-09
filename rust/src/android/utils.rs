use super::ptr_j::*;
use super::result::ToJniResult;
use super::string::*;
use crate::panic::{handle_exception_result, ToResult, Zip};
use crate::ptr::RPtrRepresentable;
use jni::objects::{JObject, JString};
use jni::sys::{jbyteArray, jobject, jint};
use jni::JNIEnv;
use crate::utils::ToFromBytes;

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


// to/from bytes

pub unsafe fn to_bytes<T: RPtrRepresentable + ToFromBytes>(
  env: JNIEnv, obj: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let obj = obj.rptr(&env)?;
    obj
      .typed_ref::<T>()
      .map(|obj| obj.to_bytes())
      .and_then(|bytes| env.byte_array_from_slice(&bytes).into_result())
      .map(|arr| JObject::from(arr))
  })
  .jresult(&env)
}

pub unsafe fn from_bytes<T: RPtrRepresentable + ToFromBytes>(
  env: JNIEnv, bytes: jbyteArray,
) -> jobject {
  handle_exception_result(|| {
    env
      .convert_byte_array(bytes)
      .into_result()
      .and_then(|bytes| T::from_bytes(bytes).into_result())
      .and_then(|obj| obj.rptr().jptr(&env))
  })
  .jresult(&env)
}

// utils from cardano_serialization_lib::utils

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_makeIcarusBootstrapWitness(
  env: JNIEnv, _: JObject, tx_body_hash: JRPtr, addr: JRPtr, key: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_body_hash = tx_body_hash.rptr(&env)?;
    let addr = addr.rptr(&env)?;
    let key = key.rptr(&env)?;
    tx_body_hash.typed_ref::<TransactionHash>()
    .zip(addr.typed_ref::<ByronAddress>())
    .zip(key.typed_ref::<Bip32PrivateKey>())
    .and_then(
      |((tx_body_hash, addr), key)| {
        make_icarus_bootstrap_witness(tx_body_hash, addr, key).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_makeVkeyWitness(
  env: JNIEnv, _: JObject, tx_body_hash: JRPtr, sk: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_body_hash = tx_body_hash.rptr(&env)?;
    let sk = sk.rptr(&env)?;
    tx_body_hash.typed_ref::<TransactionHash>().zip(sk.typed_ref::<PrivateKey>()).and_then(
      |(tx_body_hash, sk)| {
        make_vkey_witness(tx_body_hash, sk).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashTransaction(
  env: JNIEnv, _: JObject, ptr: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let tx_body = ptr.rptr(&env)?;
    tx_body
      .typed_ref::<TransactionBody>()
      .and_then(|tx_body| hash_transaction(tx_body).rptr().jptr(&env))
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_minAdaRequired(
  env: JNIEnv, _: JObject, assets: JRPtr, minimum_utxo_val: JRPtr
) -> jobject {
  handle_exception_result(|| {
    let assets = assets.rptr(&env)?;
    let minimum_utxo_val = minimum_utxo_val.rptr(&env)?;
    assets.typed_ref::<Value>().zip(minimum_utxo_val.typed_ref::<BigNum>()).and_then(
      |(assets, minimum_utxo_val)| {
        min_ada_required(assets, minimum_utxo_val).rptr().jptr(&env)
      }
    )
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encodeJsonStrToMetadatum(
  env: JNIEnv, _: JObject, json: JString, schema: jint
) -> jobject {
  handle_exception_result(|| {
    let rstr = json.string(&env)?;
    let schema = schema as i32;
    let schema_enum: MetadataJsonSchema;
    match schema {
      0 => schema_enum = MetadataJsonSchema::NoConversions,
      1 => schema_enum = MetadataJsonSchema::BasicConversions,
      2 => schema_enum = MetadataJsonSchema::DetailedSchema,
      _ => schema_enum = MetadataJsonSchema::BasicConversions,
    }
    let tx_metadatum = encode_json_str_to_metadatum(rstr, schema_enum).into_result()?;
    tx_metadatum.rptr().jptr(&env)
  })
  .jresult(&env)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decodeMetadatumToJsonStr(
  env: JNIEnv, _: JObject, metadatum: JRPtr, schema: jint
) -> jobject {
  handle_exception_result(|| {
    let metadatum = metadatum.rptr(&env)?;
    let schema = schema as i32;
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
      .and_then(|json| json.jstring(&env))
  })
  .jresult(&env)
}
