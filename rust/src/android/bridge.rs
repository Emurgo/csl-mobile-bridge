use super::bridge_tools::ptr_j::*;
use super::bridge_tools::result::*;
use crate::panic::{handle_exception_result, Zip, ToResult};
use crate::ptr::RPtrRepresentable;
use crate::ptr_impl::*;
use crate::enum_maps::*;
use crate::arrays::*;
use super::bridge_tools::boxing::*;
use super::bridge_tools::unboxing::*;
use super::bridge_tools::primitives::*;
use super::bridge_tools::utils::*;
use super::bridge_tools::string::*;
use jni::objects::{JObject, JString};
use jni::sys::{jlong, jint, jobject, jboolean, jbyteArray};
use jni::JNIEnv;
use std::convert::TryFrom;
use cardano_serialization_lib::AssetName;
use cardano_serialization_lib::AssetNames;
use cardano_serialization_lib::Assets;
use cardano_serialization_lib::AuxiliaryDataSet;
use cardano_serialization_lib::Block;
use cardano_serialization_lib::Certificate;
use cardano_serialization_lib::CertificateKind;
use cardano_serialization_lib::Certificates;
use cardano_serialization_lib::DNSRecordAorAAAA;
use cardano_serialization_lib::DNSRecordSRV;
use cardano_serialization_lib::DataCost;
use cardano_serialization_lib::Ed25519KeyHashes;
use cardano_serialization_lib::GenesisHashes;
use cardano_serialization_lib::GenesisKeyDelegation;
use cardano_serialization_lib::Header;
use cardano_serialization_lib::HeaderBody;
use cardano_serialization_lib::Ipv4;
use cardano_serialization_lib::Ipv6;
use cardano_serialization_lib::MIRKind;
use cardano_serialization_lib::MIRPot;
use cardano_serialization_lib::MIRToStakeCredentials;
use cardano_serialization_lib::Mint;
use cardano_serialization_lib::MintAssets;
use cardano_serialization_lib::MintsAssets;
use cardano_serialization_lib::MoveInstantaneousReward;
use cardano_serialization_lib::MoveInstantaneousRewardsCert;
use cardano_serialization_lib::MultiAsset;
use cardano_serialization_lib::MultiHostName;
use cardano_serialization_lib::NativeScript;
use cardano_serialization_lib::NativeScriptKind;
use cardano_serialization_lib::NativeScripts;
use cardano_serialization_lib::NetworkId;
use cardano_serialization_lib::NetworkIdKind;
use cardano_serialization_lib::OperationalCert;
use cardano_serialization_lib::PoolMetadata;
use cardano_serialization_lib::PoolParams;
use cardano_serialization_lib::PoolRegistration;
use cardano_serialization_lib::PoolRetirement;
use cardano_serialization_lib::ProposedProtocolParameterUpdates;
use cardano_serialization_lib::ProtocolParamUpdate;
use cardano_serialization_lib::ProtocolVersion;
use cardano_serialization_lib::Relay;
use cardano_serialization_lib::RelayKind;
use cardano_serialization_lib::Relays;
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::ScriptAll;
use cardano_serialization_lib::ScriptAny;
use cardano_serialization_lib::ScriptHashNamespace;
use cardano_serialization_lib::ScriptHashes;
use cardano_serialization_lib::ScriptNOfK;
use cardano_serialization_lib::ScriptPubkey;
use cardano_serialization_lib::ScriptRef;
use cardano_serialization_lib::SingleHostAddr;
use cardano_serialization_lib::SingleHostName;
use cardano_serialization_lib::StakeCredentials;
use cardano_serialization_lib::StakeDelegation;
use cardano_serialization_lib::StakeDeregistration;
use cardano_serialization_lib::StakeRegistration;
use cardano_serialization_lib::TimelockExpiry;
use cardano_serialization_lib::TimelockStart;
use cardano_serialization_lib::Transaction;
use cardano_serialization_lib::TransactionBodies;
use cardano_serialization_lib::TransactionBody;
use cardano_serialization_lib::TransactionInput;
use cardano_serialization_lib::TransactionInputs;
use cardano_serialization_lib::TransactionOutput;
use cardano_serialization_lib::TransactionOutputs;
use cardano_serialization_lib::TransactionWitnessSet;
use cardano_serialization_lib::TransactionWitnessSets;
use cardano_serialization_lib::URL;
use cardano_serialization_lib::UnitInterval;
use cardano_serialization_lib::Update;
use cardano_serialization_lib::Withdrawals;
use cardano_serialization_lib::address::Address;
use cardano_serialization_lib::address::BaseAddress;
use cardano_serialization_lib::address::ByronAddress;
use cardano_serialization_lib::address::EnterpriseAddress;
use cardano_serialization_lib::address::NetworkInfo;
use cardano_serialization_lib::address::Pointer;
use cardano_serialization_lib::address::PointerAddress;
use cardano_serialization_lib::address::RewardAddress;
use cardano_serialization_lib::address::StakeCredKind;
use cardano_serialization_lib::address::StakeCredential;
use cardano_serialization_lib::crypto::AuxiliaryDataHash;
use cardano_serialization_lib::crypto::Bip32PrivateKey;
use cardano_serialization_lib::crypto::Bip32PublicKey;
use cardano_serialization_lib::crypto::BlockHash;
use cardano_serialization_lib::crypto::BootstrapWitness;
use cardano_serialization_lib::crypto::BootstrapWitnesses;
use cardano_serialization_lib::crypto::DataHash;
use cardano_serialization_lib::crypto::Ed25519KeyHash;
use cardano_serialization_lib::crypto::Ed25519Signature;
use cardano_serialization_lib::crypto::GenesisDelegateHash;
use cardano_serialization_lib::crypto::GenesisHash;
use cardano_serialization_lib::crypto::KESSignature;
use cardano_serialization_lib::crypto::KESVKey;
use cardano_serialization_lib::crypto::LegacyDaedalusPrivateKey;
use cardano_serialization_lib::crypto::Nonce;
use cardano_serialization_lib::crypto::PoolMetadataHash;
use cardano_serialization_lib::crypto::PrivateKey;
use cardano_serialization_lib::crypto::PublicKey;
use cardano_serialization_lib::crypto::PublicKeys;
use cardano_serialization_lib::crypto::ScriptDataHash;
use cardano_serialization_lib::crypto::ScriptHash;
use cardano_serialization_lib::crypto::TransactionHash;
use cardano_serialization_lib::crypto::VRFCert;
use cardano_serialization_lib::crypto::VRFKeyHash;
use cardano_serialization_lib::crypto::VRFVKey;
use cardano_serialization_lib::crypto::Vkey;
use cardano_serialization_lib::crypto::Vkeys;
use cardano_serialization_lib::crypto::Vkeywitness;
use cardano_serialization_lib::crypto::Vkeywitnesses;
use cardano_serialization_lib::emip3::decrypt_with_password;
use cardano_serialization_lib::emip3::encrypt_with_password;
use cardano_serialization_lib::fees::LinearFee;
use cardano_serialization_lib::fees::calculate_ex_units_ceil_cost;
use cardano_serialization_lib::fees::min_fee;
use cardano_serialization_lib::fees::min_script_fee;
use cardano_serialization_lib::metadata::AuxiliaryData;
use cardano_serialization_lib::metadata::GeneralTransactionMetadata;
use cardano_serialization_lib::metadata::MetadataJsonSchema;
use cardano_serialization_lib::metadata::MetadataList;
use cardano_serialization_lib::metadata::MetadataMap;
use cardano_serialization_lib::metadata::TransactionMetadatum;
use cardano_serialization_lib::metadata::TransactionMetadatumKind;
use cardano_serialization_lib::metadata::TransactionMetadatumLabels;
use cardano_serialization_lib::metadata::decode_arbitrary_bytes_from_metadatum;
use cardano_serialization_lib::metadata::decode_metadatum_to_json_str;
use cardano_serialization_lib::metadata::encode_arbitrary_bytes_as_metadatum;
use cardano_serialization_lib::metadata::encode_json_str_to_metadatum;
use cardano_serialization_lib::output_builder::TransactionOutputAmountBuilder;
use cardano_serialization_lib::output_builder::TransactionOutputBuilder;
use cardano_serialization_lib::plutus::ConstrPlutusData;
use cardano_serialization_lib::plutus::CostModel;
use cardano_serialization_lib::plutus::Costmdls;
use cardano_serialization_lib::plutus::ExUnitPrices;
use cardano_serialization_lib::plutus::ExUnits;
use cardano_serialization_lib::plutus::Language;
use cardano_serialization_lib::plutus::LanguageKind;
use cardano_serialization_lib::plutus::Languages;
use cardano_serialization_lib::plutus::PlutusData;
use cardano_serialization_lib::plutus::PlutusDataKind;
use cardano_serialization_lib::plutus::PlutusDatumSchema;
use cardano_serialization_lib::plutus::PlutusList;
use cardano_serialization_lib::plutus::PlutusMap;
use cardano_serialization_lib::plutus::PlutusScript;
use cardano_serialization_lib::plutus::PlutusScripts;
use cardano_serialization_lib::plutus::Redeemer;
use cardano_serialization_lib::plutus::RedeemerTag;
use cardano_serialization_lib::plutus::RedeemerTagKind;
use cardano_serialization_lib::plutus::Redeemers;
use cardano_serialization_lib::plutus::Strings;
use cardano_serialization_lib::plutus::decode_plutus_datum_to_json_str;
use cardano_serialization_lib::plutus::encode_json_str_to_plutus_datum;
use cardano_serialization_lib::protocol_types::fixed_tx::FixedTransaction;
use cardano_serialization_lib::tx_builder::CoinSelectionStrategyCIP2;
use cardano_serialization_lib::tx_builder::TransactionBuilder;
use cardano_serialization_lib::tx_builder::TransactionBuilderConfig;
use cardano_serialization_lib::tx_builder::TransactionBuilderConfigBuilder;
use cardano_serialization_lib::tx_builder::mint_builder::MintBuilder;
use cardano_serialization_lib::tx_builder::mint_builder::MintWitness;
use cardano_serialization_lib::tx_builder::tx_batch_builder::TransactionBatch;
use cardano_serialization_lib::tx_builder::tx_batch_builder::TransactionBatchList;
use cardano_serialization_lib::tx_builder::tx_batch_builder::create_send_all;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::DatumSource;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::InputWithScriptWitness;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::InputsWithScriptWitness;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::PlutusScriptSource;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::PlutusWitness;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::PlutusWitnesses;
use cardano_serialization_lib::tx_builder::tx_inputs_builder::TxInputsBuilder;
use cardano_serialization_lib::tx_builder_constants::TxBuilderConstants;
use cardano_serialization_lib::utils::BigInt;
use cardano_serialization_lib::utils::BigNum;
use cardano_serialization_lib::utils::Int;
use cardano_serialization_lib::utils::ScriptSchema;
use cardano_serialization_lib::utils::TransactionUnspentOutput;
use cardano_serialization_lib::utils::TransactionUnspentOutputs;
use cardano_serialization_lib::utils::Value;
use cardano_serialization_lib::utils::encode_json_str_to_native_script;
use cardano_serialization_lib::utils::get_deposit;
use cardano_serialization_lib::utils::get_implicit_input;
use cardano_serialization_lib::utils::hash_auxiliary_data;
use cardano_serialization_lib::utils::hash_plutus_data;
use cardano_serialization_lib::utils::hash_script_data;
use cardano_serialization_lib::utils::hash_transaction;
use cardano_serialization_lib::utils::make_daedalus_bootstrap_witness;
use cardano_serialization_lib::utils::make_icarus_bootstrap_witness;
use cardano_serialization_lib::utils::make_vkey_witness;
use cardano_serialization_lib::utils::min_ada_for_output;
use cardano_serialization_lib::utils::min_ada_required;


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressFromBytes(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Address::from_bytes(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Address::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Address::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.to_bech32(None).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressToBech32WithPrefix(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(Some(prefix)).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = Address::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_addressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.network_id().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AssetName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AssetName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AssetName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameNew(env: JNIEnv, _: JObject, name_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let name = env.convert_byte_array(name_jarray).into_result()?;
    let result = AssetName::new(name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNameName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.name();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AssetNames::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AssetNames::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AssetNames::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AssetNames::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetNamesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AssetNames>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<AssetName>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Assets::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Assets::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Assets::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Assets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_assetsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AuxiliaryData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AuxiliaryData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AuxiliaryData::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AuxiliaryData::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.metadata();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr, metadata_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let metadata_jrptr = metadata_ptr.rptr(&env)?;
    let metadata = metadata_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    self_rptr.set_metadata(metadata);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, native_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let native_scripts_jrptr = native_scripts_ptr.rptr(&env)?;
    let native_scripts = native_scripts_jrptr.typed_ref::<NativeScripts>()?;
    self_rptr.set_native_scripts(native_scripts);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.plutus_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let plutus_scripts_jrptr = plutus_scripts_ptr.rptr(&env)?;
    let plutus_scripts = plutus_scripts_jrptr.typed_ref::<PlutusScripts>()?;
    self_rptr.set_plutus_scripts(plutus_scripts);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataPreferAlonzoFormat(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.prefer_alonzo_format();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetPreferAlonzoFormat(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefer_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let prefer = prefer_jboolean.into_bool();
    self_rptr.set_prefer_alonzo_format(prefer);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AuxiliaryDataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = AuxiliaryDataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = AuxiliaryDataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AuxiliaryDataSet::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataSet>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, tx_index_jlong: jlong, data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataSet>()?;
    let tx_index = u32::try_from_jlong(tx_index_jlong)?;
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.insert(tx_index, data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, tx_index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataSet>()?;
    let tx_index = u32::try_from_jlong(tx_index_jlong)?;
    let result = self_rptr.get(tx_index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_auxiliaryDataSetIndices(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryDataSet>()?;
    let result = self_rptr.indices();
    u32_array_to_base64(&result).jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_baseAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr, stake_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<StakeCredential>()?;
    let stake_jrptr = stake_ptr.rptr(&env)?;
    let stake = stake_jrptr.typed_ref::<StakeCredential>()?;
    let result = BaseAddress::new(network, payment, stake);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_baseAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BaseAddress>()?;
    let result = self_rptr.payment_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_baseAddressStakeCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BaseAddress>()?;
    let result = self_rptr.stake_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_baseAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BaseAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_baseAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = BaseAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BigInt::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BigInt::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BigInt::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.is_zero();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntAsU64(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.as_u64();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntAsInt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.as_int();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntFromStr(env: JNIEnv, _: JObject, text_str: JString) -> jobject {
  handle_exception_result(|| { 
    let text = text_str.string(&env)?;
    let result = BigInt::from_str(&text).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.to_str();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.add(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntMul(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.mul(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntOne(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigInt::one();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntIncrement(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.increment();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigIntDivCeil(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.div_ceil(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BigNum::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BigNum::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BigNum::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumFromStr(env: JNIEnv, _: JObject, string_str: JString) -> jobject {
  handle_exception_result(|| { 
    let string = string_str.string(&env)?;
    let result = BigNum::from_str(&string).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.to_str();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumZero(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::zero();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumOne(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::one();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.is_zero();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumDivFloor(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.div_floor(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumCheckedMul(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.checked_mul(other).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumCheckedAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.checked_add(other).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumCheckedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.checked_sub(other).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumClampedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.clamped_sub(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumCompare(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.compare(rhs_value);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumLessThan(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.less_than(rhs_value);
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumMaxValue(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::max_value();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bigNumMax(env: JNIEnv, _: JObject, a_ptr: JRPtr, b_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let a_jrptr = a_ptr.rptr(&env)?;
    let a = a_jrptr.typed_ref::<BigNum>()?;
    let b_jrptr = b_ptr.rptr(&env)?;
    let b = b_jrptr.typed_ref::<BigNum>()?;
    let result = BigNum::max(a, b);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyDerive(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let index = u32::try_from_jlong(index_jlong)?;
    let result = self_rptr.derive(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyFrom_128Xprv(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PrivateKey::from_128_xprv(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyTo_128Xprv(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.to_128_xprv();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyGenerateEd25519Bip32(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Bip32PrivateKey::generate_ed25519_bip32().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyToRawKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.to_raw_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyToPublic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.to_public();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PrivateKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.as_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Bip32PrivateKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.to_bech32();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyFromBip39Entropy(env: JNIEnv, _: JObject, entropy_jarray: jbyteArray, password_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let entropy = env.convert_byte_array(entropy_jarray).into_result()?;
    let password = env.convert_byte_array(password_jarray).into_result()?;
    let result = Bip32PrivateKey::from_bip39_entropy(&entropy, &password);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.chaincode();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PrivateKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Bip32PrivateKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyDerive(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let index = u32::try_from_jlong(index_jlong)?;
    let result = self_rptr.derive(index).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyToRawKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_rptr.to_raw_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PublicKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_rptr.as_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Bip32PublicKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_rptr.to_bech32();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_rptr.chaincode();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bip32PublicKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Bip32PublicKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Block::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Block::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Block::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHeader(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.header();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockTransactionBodies(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.transaction_bodies();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockTransactionWitnessSets(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.transaction_witness_sets();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockAuxiliaryDataSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.auxiliary_data_set();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockInvalidTransactions(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Block>()?;
    let result = self_rptr.invalid_transactions();
    u32_array_to_base64(&result).jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockNew(env: JNIEnv, _: JObject, header_ptr: JRPtr, transaction_bodies_ptr: JRPtr, transaction_witness_sets_ptr: JRPtr, auxiliary_data_set_ptr: JRPtr, invalid_transactions_str: JString) -> jobject {
  handle_exception_result(|| { 
    let header_jrptr = header_ptr.rptr(&env)?;
    let header = header_jrptr.typed_ref::<Header>()?;
    let transaction_bodies_jrptr = transaction_bodies_ptr.rptr(&env)?;
    let transaction_bodies = transaction_bodies_jrptr.typed_ref::<TransactionBodies>()?;
    let transaction_witness_sets_jrptr = transaction_witness_sets_ptr.rptr(&env)?;
    let transaction_witness_sets = transaction_witness_sets_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let auxiliary_data_set_jrptr = auxiliary_data_set_ptr.rptr(&env)?;
    let auxiliary_data_set = auxiliary_data_set_jrptr.typed_ref::<AuxiliaryDataSet>()?;
    let invalid_transactions = base64_to_u32_array(&invalid_transactions_str.string(&env)?)?;
    let result = Block::new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BlockHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BlockHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BlockHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = BlockHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BlockHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_blockHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = BlockHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BootstrapWitness::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BootstrapWitness::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BootstrapWitness::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.vkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessSignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.signature();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessChainCode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.chain_code();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessAttributes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.attributes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessNew(env: JNIEnv, _: JObject, vkey_ptr: JRPtr, signature_ptr: JRPtr, chain_code_jarray: jbyteArray, attributes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let vkey_jrptr = vkey_ptr.rptr(&env)?;
    let vkey = vkey_jrptr.typed_ref::<Vkey>()?;
    let signature_jrptr = signature_ptr.rptr(&env)?;
    let signature = signature_jrptr.typed_ref::<Ed25519Signature>()?;
    let chain_code = env.convert_byte_array(chain_code_jarray).into_result()?;
    let attributes = env.convert_byte_array(attributes_jarray).into_result()?;
    let result = BootstrapWitness::new(vkey, signature, chain_code, attributes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BootstrapWitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_bootstrapWitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<BootstrapWitness>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressToBase58(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.to_base58();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ByronAddress::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressByronProtocolMagic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.byron_protocol_magic();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressAttributes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.attributes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.network_id().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressFromBase58(env: JNIEnv, _: JObject, s_str: JString) -> jobject {
  handle_exception_result(|| { 
    let s = s_str.string(&env)?;
    let result = ByronAddress::from_base58(&s).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressIcarusFromKey(env: JNIEnv, _: JObject, key_ptr: JRPtr, protocol_magic_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Bip32PublicKey>()?;
    let protocol_magic = u32::try_from_jlong(protocol_magic_jlong)?;
    let result = ByronAddress::icarus_from_key(key, protocol_magic);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressIsValid(env: JNIEnv, _: JObject, s_str: JString) -> jobject {
  handle_exception_result(|| { 
    let s = s_str.string(&env)?;
    let result = ByronAddress::is_valid(&s);
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ByronAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_byronAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = ByronAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Certificate::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Certificate::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Certificate::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewStakeRegistration(env: JNIEnv, _: JObject, stake_registration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_registration_jrptr = stake_registration_ptr.rptr(&env)?;
    let stake_registration = stake_registration_jrptr.typed_ref::<StakeRegistration>()?;
    let result = Certificate::new_stake_registration(stake_registration);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewStakeDeregistration(env: JNIEnv, _: JObject, stake_deregistration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_deregistration_jrptr = stake_deregistration_ptr.rptr(&env)?;
    let stake_deregistration = stake_deregistration_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = Certificate::new_stake_deregistration(stake_deregistration);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewStakeDelegation(env: JNIEnv, _: JObject, stake_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_delegation_jrptr = stake_delegation_ptr.rptr(&env)?;
    let stake_delegation = stake_delegation_jrptr.typed_ref::<StakeDelegation>()?;
    let result = Certificate::new_stake_delegation(stake_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewPoolRegistration(env: JNIEnv, _: JObject, pool_registration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pool_registration_jrptr = pool_registration_ptr.rptr(&env)?;
    let pool_registration = pool_registration_jrptr.typed_ref::<PoolRegistration>()?;
    let result = Certificate::new_pool_registration(pool_registration);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewPoolRetirement(env: JNIEnv, _: JObject, pool_retirement_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pool_retirement_jrptr = pool_retirement_ptr.rptr(&env)?;
    let pool_retirement = pool_retirement_jrptr.typed_ref::<PoolRetirement>()?;
    let result = Certificate::new_pool_retirement(pool_retirement);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewGenesisKeyDelegation(env: JNIEnv, _: JObject, genesis_key_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let genesis_key_delegation_jrptr = genesis_key_delegation_ptr.rptr(&env)?;
    let genesis_key_delegation = genesis_key_delegation_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = Certificate::new_genesis_key_delegation(genesis_key_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateNewMoveInstantaneousRewardsCert(env: JNIEnv, _: JObject, move_instantaneous_rewards_cert_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let move_instantaneous_rewards_cert_jrptr = move_instantaneous_rewards_cert_ptr.rptr(&env)?;
    let move_instantaneous_rewards_cert = move_instantaneous_rewards_cert_jrptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = Certificate::new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsStakeRegistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_registration();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsStakeDeregistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_deregistration();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsStakeDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsPoolRegistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_pool_registration();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsPoolRetirement(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_pool_retirement();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsGenesisKeyDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_genesis_key_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificateAsMoveInstantaneousRewardsCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_move_instantaneous_rewards_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Certificates::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Certificates::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Certificates::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Certificates::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_certificatesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Certificate>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ConstrPlutusData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ConstrPlutusData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataAlternative(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_rptr.alternative();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_rptr.data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_constrPlutusDataNew(env: JNIEnv, _: JObject, alternative_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let alternative_jrptr = alternative_ptr.rptr(&env)?;
    let alternative = alternative_jrptr.typed_ref::<BigNum>()?;
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<PlutusList>()?;
    let result = ConstrPlutusData::new(alternative, data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = CostModel::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = CostModel::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = CostModel::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = CostModel::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelSet(env: JNIEnv, _: JObject, self_ptr: JRPtr, operation_jlong: jlong, cost_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let operation = usize::try_from_jlong(operation_jlong)?;
    let cost_jrptr = cost_ptr.rptr(&env)?;
    let cost = cost_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.set(operation, cost).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, operation_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let operation = usize::try_from_jlong(operation_jlong)?;
    let result = self_rptr.get(operation).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costModelLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CostModel>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Costmdls::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Costmdls::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Costmdls::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Costmdls::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Language>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<CostModel>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Language>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_costmdlsRetainLanguageVersions(env: JNIEnv, _: JObject, self_ptr: JRPtr, languages_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Costmdls>()?;
    let languages_jrptr = languages_ptr.rptr(&env)?;
    let languages = languages_jrptr.typed_ref::<Languages>()?;
    let result = self_rptr.retain_language_versions(languages);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DNSRecordAorAAAA::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DNSRecordAorAAAA::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAAFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DNSRecordAorAAAA::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAANew(env: JNIEnv, _: JObject, dns_name_str: JString) -> jobject {
  handle_exception_result(|| { 
    let dns_name = dns_name_str.string(&env)?;
    let result = DNSRecordAorAAAA::new(dns_name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordAorAAAARecord(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_rptr.record();
    result.jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DNSRecordSRV::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DNSRecordSRV::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DNSRecordSRV::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVNew(env: JNIEnv, _: JObject, dns_name_str: JString) -> jobject {
  handle_exception_result(|| { 
    let dns_name = dns_name_str.string(&env)?;
    let result = DNSRecordSRV::new(dns_name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dNSRecordSRVRecord(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_rptr.record();
    result.jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataCostNewCoinsPerWord(env: JNIEnv, _: JObject, coins_per_word_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let coins_per_word_jrptr = coins_per_word_ptr.rptr(&env)?;
    let coins_per_word = coins_per_word_jrptr.typed_ref::<BigNum>()?;
    let result = DataCost::new_coins_per_word(coins_per_word);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataCostNewCoinsPerByte(env: JNIEnv, _: JObject, coins_per_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let coins_per_byte_jrptr = coins_per_byte_ptr.rptr(&env)?;
    let coins_per_byte = coins_per_byte_jrptr.typed_ref::<BigNum>()?;
    let result = DataCost::new_coins_per_byte(coins_per_byte);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataCostCoinsPerByte(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DataCost>()?;
    let result = self_rptr.coins_per_byte();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DataHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DataHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = DataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DataHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_dataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = DataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_datumSourceNew(env: JNIEnv, _: JObject, datum_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let datum_jrptr = datum_ptr.rptr(&env)?;
    let datum = datum_jrptr.typed_ref::<PlutusData>()?;
    let result = DatumSource::new(datum);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_datumSourceNewRefInput(env: JNIEnv, _: JObject, input_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let result = DatumSource::new_ref_input(input);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519KeyHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = Ed25519KeyHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = Ed25519KeyHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519KeyHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ed25519KeyHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ed25519KeyHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Ed25519KeyHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Ed25519KeyHash>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519KeyHashesToOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_rptr.to_option();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = self_rptr.to_bech32();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Ed25519Signature::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureFromHex(env: JNIEnv, _: JObject, input_str: JString) -> jobject {
  handle_exception_result(|| { 
    let input = input_str.string(&env)?;
    let result = Ed25519Signature::from_hex(&input).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ed25519SignatureFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519Signature::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_enterpriseAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<StakeCredential>()?;
    let result = EnterpriseAddress::new(network, payment);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_enterpriseAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<EnterpriseAddress>()?;
    let result = self_rptr.payment_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_enterpriseAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<EnterpriseAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_enterpriseAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = EnterpriseAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ExUnitPrices::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ExUnitPrices::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ExUnitPrices::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesMemPrice(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.mem_price();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesStepPrice(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.step_price();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitPricesNew(env: JNIEnv, _: JObject, mem_price_ptr: JRPtr, step_price_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let mem_price_jrptr = mem_price_ptr.rptr(&env)?;
    let mem_price = mem_price_jrptr.typed_ref::<UnitInterval>()?;
    let step_price_jrptr = step_price_ptr.rptr(&env)?;
    let step_price = step_price_jrptr.typed_ref::<UnitInterval>()?;
    let result = ExUnitPrices::new(mem_price, step_price);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnits>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ExUnits::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnits>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ExUnits::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnits>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ExUnits::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsMem(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnits>()?;
    let result = self_rptr.mem();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsSteps(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ExUnits>()?;
    let result = self_rptr.steps();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_exUnitsNew(env: JNIEnv, _: JObject, mem_ptr: JRPtr, steps_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let mem_jrptr = mem_ptr.rptr(&env)?;
    let mem = mem_jrptr.typed_ref::<BigNum>()?;
    let steps_jrptr = steps_ptr.rptr(&env)?;
    let steps = steps_jrptr.typed_ref::<BigNum>()?;
    let result = ExUnits::new(mem, steps);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedTransaction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedTransaction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionNew(env: JNIEnv, _: JObject, raw_body_jarray: jbyteArray, raw_witness_set_jarray: jbyteArray, is_valid_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let raw_body = env.convert_byte_array(raw_body_jarray).into_result()?;
    let raw_witness_set = env.convert_byte_array(raw_witness_set_jarray).into_result()?;
    let is_valid = is_valid_jboolean.into_bool();
    let result = FixedTransaction::new(&raw_body, &raw_witness_set, is_valid).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionNewWithAuxiliary(env: JNIEnv, _: JObject, raw_body_jarray: jbyteArray, raw_witness_set_jarray: jbyteArray, raw_auxiliary_data_jarray: jbyteArray, is_valid_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let raw_body = env.convert_byte_array(raw_body_jarray).into_result()?;
    let raw_witness_set = env.convert_byte_array(raw_witness_set_jarray).into_result()?;
    let raw_auxiliary_data = env.convert_byte_array(raw_auxiliary_data_jarray).into_result()?;
    let is_valid = is_valid_jboolean.into_bool();
    let result = FixedTransaction::new_with_auxiliary(&raw_body, &raw_witness_set, &raw_auxiliary_data, is_valid).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.body();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionRawBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.raw_body();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionSetBody(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_body_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let raw_body = env.convert_byte_array(raw_body_jarray).into_result()?;
    self_rptr.set_body(&raw_body).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionSetWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_witness_set_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let raw_witness_set = env.convert_byte_array(raw_witness_set_jarray).into_result()?;
    self_rptr.set_witness_set(&raw_witness_set).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.witness_set();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionRawWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.raw_witness_set();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionSetIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr, valid_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let valid = valid_jboolean.into_bool();
    self_rptr.set_is_valid(valid);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.is_valid();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionSetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_auxiliary_data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let raw_auxiliary_data = env.convert_byte_array(raw_auxiliary_data_jarray).into_result()?;
    self_rptr.set_auxiliary_data(&raw_auxiliary_data).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.auxiliary_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_fixedTransactionRawAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.raw_auxiliary_data();
    match result {
        Some(result) => Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?)),
        None => Ok(JObject::null()),
    }
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GeneralTransactionMetadata::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GeneralTransactionMetadata::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GeneralTransactionMetadata::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = GeneralTransactionMetadata::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<BigNum>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_generalTransactionMetadataKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisDelegateHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisDelegateHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisDelegateHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = GenesisDelegateHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisDelegateHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisDelegateHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = GenesisDelegateHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = GenesisHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = GenesisHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GenesisHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GenesisHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = GenesisHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisHashes>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<GenesisHash>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisKeyDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GenesisKeyDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GenesisKeyDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationGenesishash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.genesishash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationGenesisDelegateHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.genesis_delegate_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationVrfKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_rptr.vrf_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_genesisKeyDelegationNew(env: JNIEnv, _: JObject, genesishash_ptr: JRPtr, genesis_delegate_hash_ptr: JRPtr, vrf_keyhash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let genesishash_jrptr = genesishash_ptr.rptr(&env)?;
    let genesishash = genesishash_jrptr.typed_ref::<GenesisHash>()?;
    let genesis_delegate_hash_jrptr = genesis_delegate_hash_ptr.rptr(&env)?;
    let genesis_delegate_hash = genesis_delegate_hash_jrptr.typed_ref::<GenesisDelegateHash>()?;
    let vrf_keyhash_jrptr = vrf_keyhash_ptr.rptr(&env)?;
    let vrf_keyhash = vrf_keyhash_jrptr.typed_ref::<VRFKeyHash>()?;
    let result = GenesisKeyDelegation::new(genesishash, genesis_delegate_hash, vrf_keyhash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Header>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Header::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Header>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Header::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Header>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Header::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerHeaderBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Header>()?;
    let result = self_rptr.header_body();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodySignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Header>()?;
    let result = self_rptr.body_signature();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerNew(env: JNIEnv, _: JObject, header_body_ptr: JRPtr, body_signature_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let header_body_jrptr = header_body_ptr.rptr(&env)?;
    let header_body = header_body_jrptr.typed_ref::<HeaderBody>()?;
    let body_signature_jrptr = body_signature_ptr.rptr(&env)?;
    let body_signature = body_signature_jrptr.typed_ref::<KESSignature>()?;
    let result = Header::new(header_body, body_signature);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = HeaderBody::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = HeaderBody::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = HeaderBody::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyBlockNumber(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.block_number();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodySlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.slot().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodySlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.slot_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyPrevHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.prev_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyIssuerVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.issuer_vkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyVrfVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.vrf_vkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyHasNonceAndLeaderVrf(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.has_nonce_and_leader_vrf();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyNonceVrfOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.nonce_vrf_or_nothing();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyLeaderVrfOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.leader_vrf_or_nothing();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyHasVrfResult(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.has_vrf_result();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyVrfResultOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.vrf_result_or_nothing();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.block_body_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyBlockBodyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.block_body_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyOperationalCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.operational_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.protocol_version();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyNew(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_jlong: jlong, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let block_number = u32::try_from_jlong(block_number_jlong)?;
    let slot = u32::try_from_jlong(slot_jlong)?;
    let issuer_vkey_jrptr = issuer_vkey_ptr.rptr(&env)?;
    let issuer_vkey = issuer_vkey_jrptr.typed_ref::<Vkey>()?;
    let vrf_vkey_jrptr = vrf_vkey_ptr.rptr(&env)?;
    let vrf_vkey = vrf_vkey_jrptr.typed_ref::<VRFVKey>()?;
    let vrf_result_jrptr = vrf_result_ptr.rptr(&env)?;
    let vrf_result = vrf_result_jrptr.typed_ref::<VRFCert>()?;
    let block_body_size = u32::try_from_jlong(block_body_size_jlong)?;
    let block_body_hash_jrptr = block_body_hash_ptr.rptr(&env)?;
    let block_body_hash = block_body_hash_jrptr.typed_ref::<BlockHash>()?;
    let operational_cert_jrptr = operational_cert_ptr.rptr(&env)?;
    let operational_cert = operational_cert_jrptr.typed_ref::<OperationalCert>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new(block_number, slot, None, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyNewWithPrevHash(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_jlong: jlong, prev_hash_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let block_number = u32::try_from_jlong(block_number_jlong)?;
    let slot = u32::try_from_jlong(slot_jlong)?;
    let prev_hash = prev_hash_ptr.rptr(&env)?.typed_ref::<BlockHash>()?.clone();
    let issuer_vkey_jrptr = issuer_vkey_ptr.rptr(&env)?;
    let issuer_vkey = issuer_vkey_jrptr.typed_ref::<Vkey>()?;
    let vrf_vkey_jrptr = vrf_vkey_ptr.rptr(&env)?;
    let vrf_vkey = vrf_vkey_jrptr.typed_ref::<VRFVKey>()?;
    let vrf_result_jrptr = vrf_result_ptr.rptr(&env)?;
    let vrf_result = vrf_result_jrptr.typed_ref::<VRFCert>()?;
    let block_body_size = u32::try_from_jlong(block_body_size_jlong)?;
    let block_body_hash_jrptr = block_body_hash_ptr.rptr(&env)?;
    let block_body_hash = block_body_hash_jrptr.typed_ref::<BlockHash>()?;
    let operational_cert_jrptr = operational_cert_ptr.rptr(&env)?;
    let operational_cert = operational_cert_jrptr.typed_ref::<OperationalCert>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new(block_number, slot, Some(prev_hash), issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyNewHeaderbody(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let block_number = u32::try_from_jlong(block_number_jlong)?;
    let slot_jrptr = slot_ptr.rptr(&env)?;
    let slot = slot_jrptr.typed_ref::<BigNum>()?;
    let issuer_vkey_jrptr = issuer_vkey_ptr.rptr(&env)?;
    let issuer_vkey = issuer_vkey_jrptr.typed_ref::<Vkey>()?;
    let vrf_vkey_jrptr = vrf_vkey_ptr.rptr(&env)?;
    let vrf_vkey = vrf_vkey_jrptr.typed_ref::<VRFVKey>()?;
    let vrf_result_jrptr = vrf_result_ptr.rptr(&env)?;
    let vrf_result = vrf_result_jrptr.typed_ref::<VRFCert>()?;
    let block_body_size = u32::try_from_jlong(block_body_size_jlong)?;
    let block_body_hash_jrptr = block_body_hash_ptr.rptr(&env)?;
    let block_body_hash = block_body_hash_jrptr.typed_ref::<BlockHash>()?;
    let operational_cert_jrptr = operational_cert_ptr.rptr(&env)?;
    let operational_cert = operational_cert_jrptr.typed_ref::<OperationalCert>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new_headerbody(block_number, slot, None, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_headerBodyNewHeaderbodyWithPrevHash(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_ptr: JRPtr, prev_hash_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let block_number = u32::try_from_jlong(block_number_jlong)?;
    let slot_jrptr = slot_ptr.rptr(&env)?;
    let slot = slot_jrptr.typed_ref::<BigNum>()?;
    let prev_hash = prev_hash_ptr.rptr(&env)?.typed_ref::<BlockHash>()?.clone();
    let issuer_vkey_jrptr = issuer_vkey_ptr.rptr(&env)?;
    let issuer_vkey = issuer_vkey_jrptr.typed_ref::<Vkey>()?;
    let vrf_vkey_jrptr = vrf_vkey_ptr.rptr(&env)?;
    let vrf_vkey = vrf_vkey_jrptr.typed_ref::<VRFVKey>()?;
    let vrf_result_jrptr = vrf_result_ptr.rptr(&env)?;
    let vrf_result = vrf_result_jrptr.typed_ref::<VRFCert>()?;
    let block_body_size = u32::try_from_jlong(block_body_size_jlong)?;
    let block_body_hash_jrptr = block_body_hash_ptr.rptr(&env)?;
    let block_body_hash = block_body_hash_jrptr.typed_ref::<BlockHash>()?;
    let operational_cert_jrptr = operational_cert_ptr.rptr(&env)?;
    let operational_cert = operational_cert_jrptr.typed_ref::<OperationalCert>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new_headerbody(block_number, slot, Some(prev_hash), issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputWithScriptWitnessNewWithNativeScriptWitness(env: JNIEnv, _: JObject, input_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<NativeScript>()?;
    let result = InputWithScriptWitness::new_with_native_script_witness(input, witness);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputWithScriptWitnessNewWithPlutusWitness(env: JNIEnv, _: JObject, input_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    let result = InputWithScriptWitness::new_with_plutus_witness(input, witness);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputWithScriptWitnessInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<InputWithScriptWitness>()?;
    let result = self_rptr.input();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputsWithScriptWitnessNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = InputsWithScriptWitness::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputsWithScriptWitnessAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, input_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<InputsWithScriptWitness>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<InputWithScriptWitness>()?;
    self_rptr.add(input);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputsWithScriptWitnessGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<InputsWithScriptWitness>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_inputsWithScriptWitnessLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<InputsWithScriptWitness>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Int::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Int::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Int::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intNew(env: JNIEnv, _: JObject, x_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let x_jrptr = x_ptr.rptr(&env)?;
    let x = x_jrptr.typed_ref::<BigNum>()?;
    let result = Int::new(x);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intNewNegative(env: JNIEnv, _: JObject, x_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let x_jrptr = x_ptr.rptr(&env)?;
    let x = x_jrptr.typed_ref::<BigNum>()?;
    let result = Int::new_negative(x);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intNewI32(env: JNIEnv, _: JObject, x_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let x = i32::try_from_jlong(x_jlong)?;
    let result = Int::new_i32(x);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intIsPositive(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.is_positive();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intAsPositive(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.as_positive();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intAsNegative(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.as_negative();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intAsI32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.as_i32();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intAsI32OrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.as_i32_or_nothing();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intAsI32OrFail(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.as_i32_or_fail().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.to_str();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_intFromStr(env: JNIEnv, _: JObject, string_str: JString) -> jobject {
  handle_exception_result(|| { 
    let string = string_str.string(&env)?;
    let result = Int::from_str(&string).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4ToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv4>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4FromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ipv4::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4ToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv4>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4FromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ipv4::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4ToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv4>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4FromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ipv4::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4New(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Ipv4::new(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv4Ip(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv4>()?;
    let result = self_rptr.ip();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6ToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv6>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6FromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ipv6::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6ToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv6>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6FromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ipv6::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6ToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv6>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6FromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ipv6::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6New(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Ipv6::new(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_ipv6Ip(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ipv6>()?;
    let result = self_rptr.ip();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESSignatureToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<KESSignature>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESSignatureFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = KESSignature::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = KESVKey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<KESVKey>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<KESVKey>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = KESVKey::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<KESVKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_kESVKeyFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = KESVKey::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Language>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Language::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Language>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Language::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Language>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Language::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageNewPlutusV1(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v1();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageNewPlutusV2(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v2();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languageKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Language>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languagesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Languages::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languagesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Languages>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languagesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Languages>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languagesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Languages>()?;
    let elem = elem_ptr.rptr(&env)?.typed_ref::<Language>()?.clone();
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_languagesList(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Languages::list();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_legacyDaedalusPrivateKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = LegacyDaedalusPrivateKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_legacyDaedalusPrivateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = self_rptr.as_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_legacyDaedalusPrivateKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = self_rptr.chaincode();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_linearFeeConstant(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<LinearFee>()?;
    let result = self_rptr.constant();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_linearFeeCoefficient(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<LinearFee>()?;
    let result = self_rptr.coefficient();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_linearFeeNew(env: JNIEnv, _: JObject, coefficient_ptr: JRPtr, constant_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let coefficient_jrptr = coefficient_ptr.rptr(&env)?;
    let coefficient = coefficient_jrptr.typed_ref::<BigNum>()?;
    let constant_jrptr = constant_ptr.rptr(&env)?;
    let constant = constant_jrptr.typed_ref::<BigNum>()?;
    let result = LinearFee::new(coefficient, constant);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MIRToStakeCredentials::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MIRToStakeCredentials::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MIRToStakeCredentials::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MIRToStakeCredentials::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, cred_ptr: JRPtr, delta_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<StakeCredential>()?;
    let delta_jrptr = delta_ptr.rptr(&env)?;
    let delta = delta_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.insert(cred, delta);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, cred_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.get(cred);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mIRToStakeCredentialsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataList>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MetadataList::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataList>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MetadataList::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MetadataList::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataList>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataList>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataListAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataList>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionMetadatum>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MetadataMap::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MetadataMap::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MetadataMap::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<TransactionMetadatum>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapInsertStr(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_str: JString, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key = key_str.string(&env)?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.insert_str(&key, value).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapInsertI32(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_jlong: jlong, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key = i32::try_from_jlong(key_jlong)?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.insert_i32(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.get(key).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapGetStr(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key = key_str.string(&env)?;
    let result = self_rptr.get_str(&key).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapGetI32(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key = i32::try_from_jlong(key_jlong)?;
    let result = self_rptr.get_i32(key).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapHas(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.has(key);
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_metadataMapKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Mint::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Mint::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Mint::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Mint::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintNewFromEntry(env: JNIEnv, _: JObject, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<ScriptHash>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<MintAssets>()?;
    let result = Mint::new_from_entry(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<ScriptHash>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<MintAssets>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<ScriptHash>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintGetAll(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<ScriptHash>()?;
    let result = self_rptr.get_all(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAsPositiveMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.as_positive_multiasset();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAsNegativeMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Mint>()?;
    let result = self_rptr.as_negative_multiasset();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MintAssets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsNewFromEntry(env: JNIEnv, _: JObject, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let value = value_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    let result = MintAssets::new_from_entry(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintAssets>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintAssets>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let value = value_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintAssets>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintAssetsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintAssets>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MintBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderAddAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<MintWitness>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    self_rptr.add_asset(mint, asset_name, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderSetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<MintWitness>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    self_rptr.set_asset(mint, asset_name, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.build();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderGetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.get_native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.get_plutus_witnesses();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderGetRedeeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.get_redeeemers().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintBuilderHasNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.has_native_scripts();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintWitnessNewNativeScript(env: JNIEnv, _: JObject, native_script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let native_script_jrptr = native_script_ptr.rptr(&env)?;
    let native_script = native_script_jrptr.typed_ref::<NativeScript>()?;
    let result = MintWitness::new_native_script(native_script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_mintWitnessNewPlutusScript(env: JNIEnv, _: JObject, plutus_script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let plutus_script_jrptr = plutus_script_ptr.rptr(&env)?;
    let plutus_script = plutus_script_jrptr.typed_ref::<PlutusScriptSource>()?;
    let redeemer_jrptr = redeemer_ptr.rptr(&env)?;
    let redeemer = redeemer_jrptr.typed_ref::<Redeemer>()?;
    let result = MintWitness::new_plutus_script(plutus_script, redeemer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MoveInstantaneousReward::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MoveInstantaneousReward::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MoveInstantaneousReward::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardNewToOtherPot(env: JNIEnv, _: JObject, pot_jint: jint, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pot = pot_jint.to_enum()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<BigNum>()?;
    let result = MoveInstantaneousReward::new_to_other_pot(pot, amount);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardNewToStakeCreds(env: JNIEnv, _: JObject, pot_jint: jint, amounts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pot = pot_jint.to_enum()?;
    let amounts_jrptr = amounts_ptr.rptr(&env)?;
    let amounts = amounts_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = MoveInstantaneousReward::new_to_stake_creds(pot, amounts);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardPot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.pot();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardAsToOtherPot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.as_to_other_pot();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardAsToStakeCreds(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_rptr.as_to_stake_creds();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MoveInstantaneousRewardsCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MoveInstantaneousRewardsCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MoveInstantaneousRewardsCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertMoveInstantaneousReward(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_rptr.move_instantaneous_reward();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_moveInstantaneousRewardsCertNew(env: JNIEnv, _: JObject, move_instantaneous_reward_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let move_instantaneous_reward_jrptr = move_instantaneous_reward_ptr.rptr(&env)?;
    let move_instantaneous_reward = move_instantaneous_reward_jrptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = MoveInstantaneousRewardsCert::new(move_instantaneous_reward);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MultiAsset::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MultiAsset::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MultiAsset::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MultiAsset::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, assets_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let policy_id_jrptr = policy_id_ptr.rptr(&env)?;
    let policy_id = policy_id_jrptr.typed_ref::<ScriptHash>()?;
    let assets_jrptr = assets_ptr.rptr(&env)?;
    let assets = assets_jrptr.typed_ref::<Assets>()?;
    let result = self_rptr.insert(policy_id, assets);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let policy_id_jrptr = policy_id_ptr.rptr(&env)?;
    let policy_id = policy_id_jrptr.typed_ref::<ScriptHash>()?;
    let result = self_rptr.get(policy_id);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetSetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, asset_name_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let policy_id_jrptr = policy_id_ptr.rptr(&env)?;
    let policy_id = policy_id_jrptr.typed_ref::<ScriptHash>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let value = value_ptr.rptr(&env)?.typed_ref::<BigNum>()?.clone();
    let result = self_rptr.set_asset(policy_id, asset_name, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetGetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, asset_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let policy_id_jrptr = policy_id_ptr.rptr(&env)?;
    let policy_id = policy_id_jrptr.typed_ref::<ScriptHash>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let result = self_rptr.get_asset(policy_id, asset_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiAssetSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_ma_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let rhs_ma_jrptr = rhs_ma_ptr.rptr(&env)?;
    let rhs_ma = rhs_ma_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.sub(rhs_ma);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiHostName>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MultiHostName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiHostName>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MultiHostName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiHostName>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MultiHostName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameDnsName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiHostName>()?;
    let result = self_rptr.dns_name();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_multiHostNameNew(env: JNIEnv, _: JObject, dns_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let dns_name_jrptr = dns_name_ptr.rptr(&env)?;
    let dns_name = dns_name_jrptr.typed_ref::<DNSRecordSRV>()?;
    let result = MultiHostName::new(dns_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NativeScript::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NativeScript::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NativeScript::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewScriptPubkey(env: JNIEnv, _: JObject, script_pubkey_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_pubkey_jrptr = script_pubkey_ptr.rptr(&env)?;
    let script_pubkey = script_pubkey_jrptr.typed_ref::<ScriptPubkey>()?;
    let result = NativeScript::new_script_pubkey(script_pubkey);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewScriptAll(env: JNIEnv, _: JObject, script_all_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_all_jrptr = script_all_ptr.rptr(&env)?;
    let script_all = script_all_jrptr.typed_ref::<ScriptAll>()?;
    let result = NativeScript::new_script_all(script_all);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewScriptAny(env: JNIEnv, _: JObject, script_any_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_any_jrptr = script_any_ptr.rptr(&env)?;
    let script_any = script_any_jrptr.typed_ref::<ScriptAny>()?;
    let result = NativeScript::new_script_any(script_any);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewScriptNOfK(env: JNIEnv, _: JObject, script_n_of_k_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_n_of_k_jrptr = script_n_of_k_ptr.rptr(&env)?;
    let script_n_of_k = script_n_of_k_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = NativeScript::new_script_n_of_k(script_n_of_k);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewTimelockStart(env: JNIEnv, _: JObject, timelock_start_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let timelock_start_jrptr = timelock_start_ptr.rptr(&env)?;
    let timelock_start = timelock_start_jrptr.typed_ref::<TimelockStart>()?;
    let result = NativeScript::new_timelock_start(timelock_start);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptNewTimelockExpiry(env: JNIEnv, _: JObject, timelock_expiry_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let timelock_expiry_jrptr = timelock_expiry_ptr.rptr(&env)?;
    let timelock_expiry = timelock_expiry_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = NativeScript::new_timelock_expiry(timelock_expiry);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsScriptPubkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_script_pubkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsScriptAll(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_script_all();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsScriptAny(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_script_any();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsScriptNOfK(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_script_n_of_k();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsTimelockStart(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_timelock_start();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptAsTimelockExpiry(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.as_timelock_expiry();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptGetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScript>()?;
    let result = self_rptr.get_required_signers();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NativeScripts::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nativeScriptsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<NativeScript>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkId>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NetworkId::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkId>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NetworkId::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkId>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NetworkId::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdTestnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkId::testnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdMainnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkId::mainnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkIdKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkId>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoNew(env: JNIEnv, _: JObject, network_id_jlong: jlong, protocol_magic_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let network_id = u8::try_from_jlong(network_id_jlong)?;
    let protocol_magic = u32::try_from_jlong(protocol_magic_jlong)?;
    let result = NetworkInfo::new(network_id, protocol_magic);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkInfo>()?;
    let result = self_rptr.network_id();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoProtocolMagic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NetworkInfo>()?;
    let result = self_rptr.protocol_magic();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoTestnetPreview(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preview();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoTestnetPreprod(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preprod();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoTestnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_networkInfoMainnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::mainnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Nonce>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Nonce::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Nonce>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Nonce::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Nonce>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Nonce::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceNewIdentity(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Nonce::new_identity();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceNewFromHash(env: JNIEnv, _: JObject, hash_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let hash = env.convert_byte_array(hash_jarray).into_result()?;
    let result = Nonce::new_from_hash(hash).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_nonceGetHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Nonce>()?;
    let result = self_rptr.get_hash();
    match result {
        Some(result) => Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?)),
        None => Ok(JObject::null()),
    }
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = OperationalCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = OperationalCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = OperationalCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertHotVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.hot_vkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertSequenceNumber(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.sequence_number();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertKesPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.kes_period();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertSigma(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OperationalCert>()?;
    let result = self_rptr.sigma();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_operationalCertNew(env: JNIEnv, _: JObject, hot_vkey_ptr: JRPtr, sequence_number_jlong: jlong, kes_period_jlong: jlong, sigma_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hot_vkey_jrptr = hot_vkey_ptr.rptr(&env)?;
    let hot_vkey = hot_vkey_jrptr.typed_ref::<KESVKey>()?;
    let sequence_number = u32::try_from_jlong(sequence_number_jlong)?;
    let kes_period = u32::try_from_jlong(kes_period_jlong)?;
    let sigma_jrptr = sigma_ptr.rptr(&env)?;
    let sigma = sigma_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = OperationalCert::new(hot_vkey, sequence_number, kes_period, sigma);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewConstrPlutusData(env: JNIEnv, _: JObject, constr_plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let constr_plutus_data_jrptr = constr_plutus_data_ptr.rptr(&env)?;
    let constr_plutus_data = constr_plutus_data_jrptr.typed_ref::<ConstrPlutusData>()?;
    let result = PlutusData::new_constr_plutus_data(constr_plutus_data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewEmptyConstrPlutusData(env: JNIEnv, _: JObject, alternative_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let alternative_jrptr = alternative_ptr.rptr(&env)?;
    let alternative = alternative_jrptr.typed_ref::<BigNum>()?;
    let result = PlutusData::new_empty_constr_plutus_data(alternative);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewMap(env: JNIEnv, _: JObject, map_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let map_jrptr = map_ptr.rptr(&env)?;
    let map = map_jrptr.typed_ref::<PlutusMap>()?;
    let result = PlutusData::new_map(map);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewList(env: JNIEnv, _: JObject, list_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let list_jrptr = list_ptr.rptr(&env)?;
    let list = list_jrptr.typed_ref::<PlutusList>()?;
    let result = PlutusData::new_list(list);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewInteger(env: JNIEnv, _: JObject, integer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let integer_jrptr = integer_ptr.rptr(&env)?;
    let integer = integer_jrptr.typed_ref::<BigInt>()?;
    let result = PlutusData::new_integer(integer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataNewBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusData::new_bytes(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataAsConstrPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.as_constr_plutus_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataAsMap(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.as_map();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataAsList(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.as_list();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataAsInteger(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.as_integer();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.as_bytes();
    match result {
        Some(result) => Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?)),
        None => Ok(JObject::null()),
    }
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusData>()?;
    let schema = schema_jint.to_enum()?;
    let result = self_rptr.to_json(schema).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusDataFromJson(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    let result = PlutusData::from_json(&json, schema).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusList>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusList::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusList>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusList::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusList::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusList>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusList>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusListAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusList>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<PlutusData>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusMap::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusMap::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusMap::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<PlutusData>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusMapKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScript>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScript>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusScript::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptNew(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::new(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptNewV2(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::new_v2(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptNewWithVersion(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray, language_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let language_jrptr = language_ptr.rptr(&env)?;
    let language = language_jrptr.typed_ref::<Language>()?;
    let result = PlutusScript::new_with_version(bytes, language);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScript>()?;
    let result = self_rptr.bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptFromBytesV2(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::from_bytes_v2(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptFromBytesWithVersion(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray, language_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let language_jrptr = language_ptr.rptr(&env)?;
    let language = language_jrptr.typed_ref::<Language>()?;
    let result = PlutusScript::from_bytes_with_version(bytes, language).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptFromHexWithVersion(env: JNIEnv, _: JObject, hex_str_str: JString, language_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let language_jrptr = language_ptr.rptr(&env)?;
    let language = language_jrptr.typed_ref::<Language>()?;
    let result = PlutusScript::from_hex_with_version(&hex_str, language).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScript>()?;
    let result = self_rptr.hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptLanguageVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScript>()?;
    let result = self_rptr.language_version();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptSourceNew(env: JNIEnv, _: JObject, script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<PlutusScript>()?;
    let result = PlutusScriptSource::new(script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptSourceNewRefInput(env: JNIEnv, _: JObject, script_hash_ptr: JRPtr, input_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let result = PlutusScriptSource::new_ref_input(script_hash, input);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptSourceNewRefInputWithLangVer(env: JNIEnv, _: JObject, script_hash_ptr: JRPtr, input_ptr: JRPtr, lang_ver_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let lang_ver_jrptr = lang_ver_ptr.rptr(&env)?;
    let lang_ver = lang_ver_jrptr.typed_ref::<Language>()?;
    let result = PlutusScriptSource::new_ref_input_with_lang_ver(script_hash, input, lang_ver);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScripts::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusScripts::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PlutusScripts::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusScripts::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusScriptsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScripts>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<PlutusScript>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessNew(env: JNIEnv, _: JObject, script_ptr: JRPtr, datum_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<PlutusScript>()?;
    let datum_jrptr = datum_ptr.rptr(&env)?;
    let datum = datum_jrptr.typed_ref::<PlutusData>()?;
    let redeemer_jrptr = redeemer_ptr.rptr(&env)?;
    let redeemer = redeemer_jrptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new(script, datum, redeemer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessNewWithRef(env: JNIEnv, _: JObject, script_ptr: JRPtr, datum_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<PlutusScriptSource>()?;
    let datum_jrptr = datum_ptr.rptr(&env)?;
    let datum = datum_jrptr.typed_ref::<DatumSource>()?;
    let redeemer_jrptr = redeemer_ptr.rptr(&env)?;
    let redeemer = redeemer_jrptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_with_ref(script, datum, redeemer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessNewWithoutDatum(env: JNIEnv, _: JObject, script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<PlutusScript>()?;
    let redeemer_jrptr = redeemer_ptr.rptr(&env)?;
    let redeemer = redeemer_jrptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_without_datum(script, redeemer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessNewWithRefWithoutDatum(env: JNIEnv, _: JObject, script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<PlutusScriptSource>()?;
    let redeemer_jrptr = redeemer_ptr.rptr(&env)?;
    let redeemer = redeemer_jrptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_with_ref_without_datum(script, redeemer);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitness>()?;
    let result = self_rptr.script();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessDatum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitness>()?;
    let result = self_rptr.datum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessRedeemer(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitness>()?;
    let result = self_rptr.redeemer();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusWitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitnesses>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitnesses>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_plutusWitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusWitnesses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<PlutusWitness>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerNew(env: JNIEnv, _: JObject, slot_jlong: jlong, tx_index_jlong: jlong, cert_index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let slot = u32::try_from_jlong(slot_jlong)?;
    let tx_index = u32::try_from_jlong(tx_index_jlong)?;
    let cert_index = u32::try_from_jlong(cert_index_jlong)?;
    let result = Pointer::new(slot, tx_index, cert_index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerNewPointer(env: JNIEnv, _: JObject, slot_ptr: JRPtr, tx_index_ptr: JRPtr, cert_index_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let slot_jrptr = slot_ptr.rptr(&env)?;
    let slot = slot_jrptr.typed_ref::<BigNum>()?;
    let tx_index_jrptr = tx_index_ptr.rptr(&env)?;
    let tx_index = tx_index_jrptr.typed_ref::<BigNum>()?;
    let cert_index_jrptr = cert_index_ptr.rptr(&env)?;
    let cert_index = cert_index_jrptr.typed_ref::<BigNum>()?;
    let result = Pointer::new_pointer(slot, tx_index, cert_index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerSlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.slot().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerTxIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.tx_index().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerCertIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.cert_index().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerSlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.slot_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerTxIndexBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.tx_index_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerCertIndexBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Pointer>()?;
    let result = self_rptr.cert_index_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr, stake_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<StakeCredential>()?;
    let stake_jrptr = stake_ptr.rptr(&env)?;
    let stake = stake_jrptr.typed_ref::<Pointer>()?;
    let result = PointerAddress::new(network, payment, stake);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PointerAddress>()?;
    let result = self_rptr.payment_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerAddressStakePointer(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PointerAddress>()?;
    let result = self_rptr.stake_pointer();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PointerAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_pointerAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = PointerAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadata>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolMetadata::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadata>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolMetadata::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadata>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolMetadata::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataUrl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadata>()?;
    let result = self_rptr.url();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataPoolMetadataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadata>()?;
    let result = self_rptr.pool_metadata_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataNew(env: JNIEnv, _: JObject, url_ptr: JRPtr, pool_metadata_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let url_jrptr = url_ptr.rptr(&env)?;
    let url = url_jrptr.typed_ref::<URL>()?;
    let pool_metadata_hash_jrptr = pool_metadata_hash_ptr.rptr(&env)?;
    let pool_metadata_hash = pool_metadata_hash_jrptr.typed_ref::<PoolMetadataHash>()?;
    let result = PoolMetadata::new(url, pool_metadata_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolMetadataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadataHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadataHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = PoolMetadataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolMetadataHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolMetadataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = PoolMetadataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolParams::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolParams::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolParams::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsOperator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.operator();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsVrfKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.vrf_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsPledge(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.pledge();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsCost(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.cost();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsMargin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.margin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsRewardAccount(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.reward_account();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsPoolOwners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.pool_owners();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsRelays(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.relays();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsPoolMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolParams>()?;
    let result = self_rptr.pool_metadata();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsNew(env: JNIEnv, _: JObject, operator_ptr: JRPtr, vrf_keyhash_ptr: JRPtr, pledge_ptr: JRPtr, cost_ptr: JRPtr, margin_ptr: JRPtr, reward_account_ptr: JRPtr, pool_owners_ptr: JRPtr, relays_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let operator_jrptr = operator_ptr.rptr(&env)?;
    let operator = operator_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let vrf_keyhash_jrptr = vrf_keyhash_ptr.rptr(&env)?;
    let vrf_keyhash = vrf_keyhash_jrptr.typed_ref::<VRFKeyHash>()?;
    let pledge_jrptr = pledge_ptr.rptr(&env)?;
    let pledge = pledge_jrptr.typed_ref::<BigNum>()?;
    let cost_jrptr = cost_ptr.rptr(&env)?;
    let cost = cost_jrptr.typed_ref::<BigNum>()?;
    let margin_jrptr = margin_ptr.rptr(&env)?;
    let margin = margin_jrptr.typed_ref::<UnitInterval>()?;
    let reward_account_jrptr = reward_account_ptr.rptr(&env)?;
    let reward_account = reward_account_jrptr.typed_ref::<RewardAddress>()?;
    let pool_owners_jrptr = pool_owners_ptr.rptr(&env)?;
    let pool_owners = pool_owners_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let relays_jrptr = relays_ptr.rptr(&env)?;
    let relays = relays_jrptr.typed_ref::<Relays>()?;
    let result = PoolParams::new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolParamsNewWithPoolMetadata(env: JNIEnv, _: JObject, operator_ptr: JRPtr, vrf_keyhash_ptr: JRPtr, pledge_ptr: JRPtr, cost_ptr: JRPtr, margin_ptr: JRPtr, reward_account_ptr: JRPtr, pool_owners_ptr: JRPtr, relays_ptr: JRPtr, pool_metadata_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let operator_jrptr = operator_ptr.rptr(&env)?;
    let operator = operator_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let vrf_keyhash_jrptr = vrf_keyhash_ptr.rptr(&env)?;
    let vrf_keyhash = vrf_keyhash_jrptr.typed_ref::<VRFKeyHash>()?;
    let pledge_jrptr = pledge_ptr.rptr(&env)?;
    let pledge = pledge_jrptr.typed_ref::<BigNum>()?;
    let cost_jrptr = cost_ptr.rptr(&env)?;
    let cost = cost_jrptr.typed_ref::<BigNum>()?;
    let margin_jrptr = margin_ptr.rptr(&env)?;
    let margin = margin_jrptr.typed_ref::<UnitInterval>()?;
    let reward_account_jrptr = reward_account_ptr.rptr(&env)?;
    let reward_account = reward_account_jrptr.typed_ref::<RewardAddress>()?;
    let pool_owners_jrptr = pool_owners_ptr.rptr(&env)?;
    let pool_owners = pool_owners_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let relays_jrptr = relays_ptr.rptr(&env)?;
    let relays = relays_jrptr.typed_ref::<Relays>()?;
    let pool_metadata = pool_metadata_ptr.rptr(&env)?.typed_ref::<PoolMetadata>()?.clone();
    let result = PoolParams::new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, Some(pool_metadata));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRegistration>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolRegistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRegistration>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolRegistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRegistration>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolRegistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationPoolParams(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRegistration>()?;
    let result = self_rptr.pool_params();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRegistrationNew(env: JNIEnv, _: JObject, pool_params_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pool_params_jrptr = pool_params_ptr.rptr(&env)?;
    let pool_params = pool_params_jrptr.typed_ref::<PoolParams>()?;
    let result = PoolRegistration::new(pool_params);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRetirement>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolRetirement::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRetirement>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolRetirement::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRetirement>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolRetirement::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRetirement>()?;
    let result = self_rptr.pool_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolRetirement>()?;
    let result = self_rptr.epoch();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_poolRetirementNew(env: JNIEnv, _: JObject, pool_keyhash_ptr: JRPtr, epoch_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let epoch = u32::try_from_jlong(epoch_jlong)?;
    let result = PoolRetirement::new(pool_keyhash, epoch);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyToPublic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PrivateKey>()?;
    let result = self_rptr.to_public();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyGenerateEd25519(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyGenerateEd25519extended(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519extended().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = PrivateKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PrivateKey>()?;
    let result = self_rptr.to_bech32();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PrivateKey>()?;
    let result = self_rptr.as_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyFromExtendedBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PrivateKey::from_extended_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyFromNormalBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PrivateKey::from_normal_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeySign(env: JNIEnv, _: JObject, self_ptr: JRPtr, message_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PrivateKey>()?;
    let message = env.convert_byte_array(message_jarray).into_result()?;
    let result = self_rptr.sign(&message);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PrivateKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_privateKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PrivateKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProposedProtocolParameterUpdates::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProposedProtocolParameterUpdates::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProposedProtocolParameterUpdates::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ProposedProtocolParameterUpdates::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<GenesisHash>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<GenesisHash>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_proposedProtocolParameterUpdatesKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProtocolParamUpdate::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProtocolParamUpdate::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProtocolParamUpdate::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMinfeeA(env: JNIEnv, _: JObject, self_ptr: JRPtr, minfee_a_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let minfee_a_jrptr = minfee_a_ptr.rptr(&env)?;
    let minfee_a = minfee_a_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_minfee_a(minfee_a);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMinfeeA(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.minfee_a();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMinfeeB(env: JNIEnv, _: JObject, self_ptr: JRPtr, minfee_b_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let minfee_b_jrptr = minfee_b_ptr.rptr(&env)?;
    let minfee_b = minfee_b_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_minfee_b(minfee_b);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMinfeeB(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.minfee_b();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_body_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_body_size = u32::try_from_jlong(max_block_body_size_jlong)?;
    self_rptr.set_max_block_body_size(max_block_body_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_block_body_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_tx_size = u32::try_from_jlong(max_tx_size_jlong)?;
    self_rptr.set_max_tx_size(max_tx_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_tx_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxBlockHeaderSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_header_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_header_size = u32::try_from_jlong(max_block_header_size_jlong)?;
    self_rptr.set_max_block_header_size(max_block_header_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxBlockHeaderSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_block_header_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_key_deposit(key_deposit);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.key_deposit();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetPoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_pool_deposit(pool_deposit);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdatePoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.pool_deposit();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_epoch_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_epoch = u32::try_from_jlong(max_epoch_jlong)?;
    self_rptr.set_max_epoch(max_epoch);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_epoch();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetNOpt(env: JNIEnv, _: JObject, self_ptr: JRPtr, n_opt_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let n_opt = u32::try_from_jlong(n_opt_jlong)?;
    self_rptr.set_n_opt(n_opt);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateNOpt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.n_opt();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetPoolPledgeInfluence(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_pledge_influence_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_pledge_influence_jrptr = pool_pledge_influence_ptr.rptr(&env)?;
    let pool_pledge_influence = pool_pledge_influence_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_pool_pledge_influence(pool_pledge_influence);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdatePoolPledgeInfluence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.pool_pledge_influence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetExpansionRate(env: JNIEnv, _: JObject, self_ptr: JRPtr, expansion_rate_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let expansion_rate_jrptr = expansion_rate_ptr.rptr(&env)?;
    let expansion_rate = expansion_rate_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_expansion_rate(expansion_rate);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateExpansionRate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.expansion_rate();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetTreasuryGrowthRate(env: JNIEnv, _: JObject, self_ptr: JRPtr, treasury_growth_rate_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let treasury_growth_rate_jrptr = treasury_growth_rate_ptr.rptr(&env)?;
    let treasury_growth_rate = treasury_growth_rate_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_treasury_growth_rate(treasury_growth_rate);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateTreasuryGrowthRate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.treasury_growth_rate();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateD(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.d();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateExtraEntropy(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.extra_entropy();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    self_rptr.set_protocol_version(protocol_version);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.protocol_version();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMinPoolCost(env: JNIEnv, _: JObject, self_ptr: JRPtr, min_pool_cost_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let min_pool_cost_jrptr = min_pool_cost_ptr.rptr(&env)?;
    let min_pool_cost = min_pool_cost_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_min_pool_cost(min_pool_cost);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMinPoolCost(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.min_pool_cost();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetAdaPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, ada_per_utxo_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let ada_per_utxo_byte_jrptr = ada_per_utxo_byte_ptr.rptr(&env)?;
    let ada_per_utxo_byte = ada_per_utxo_byte_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_ada_per_utxo_byte(ada_per_utxo_byte);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateAdaPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.ada_per_utxo_byte();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetCostModels(env: JNIEnv, _: JObject, self_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let cost_models_jrptr = cost_models_ptr.rptr(&env)?;
    let cost_models = cost_models_jrptr.typed_ref::<Costmdls>()?;
    self_rptr.set_cost_models(cost_models);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateCostModels(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetExecutionCosts(env: JNIEnv, _: JObject, self_ptr: JRPtr, execution_costs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let execution_costs_jrptr = execution_costs_ptr.rptr(&env)?;
    let execution_costs = execution_costs_jrptr.typed_ref::<ExUnitPrices>()?;
    self_rptr.set_execution_costs(execution_costs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateExecutionCosts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.execution_costs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxTxExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_ex_units_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_tx_ex_units_jrptr = max_tx_ex_units_ptr.rptr(&env)?;
    let max_tx_ex_units = max_tx_ex_units_jrptr.typed_ref::<ExUnits>()?;
    self_rptr.set_max_tx_ex_units(max_tx_ex_units);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxTxExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_tx_ex_units();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxBlockExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_ex_units_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_ex_units_jrptr = max_block_ex_units_ptr.rptr(&env)?;
    let max_block_ex_units = max_block_ex_units_jrptr.typed_ref::<ExUnits>()?;
    self_rptr.set_max_block_ex_units(max_block_ex_units);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxBlockExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_block_ex_units();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_value_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_value_size = u32::try_from_jlong(max_value_size_jlong)?;
    self_rptr.set_max_value_size(max_value_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_value_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetCollateralPercentage(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_percentage_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let collateral_percentage = u32::try_from_jlong(collateral_percentage_jlong)?;
    self_rptr.set_collateral_percentage(collateral_percentage);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateCollateralPercentage(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.collateral_percentage();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateSetMaxCollateralInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_collateral_inputs_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_collateral_inputs = u32::try_from_jlong(max_collateral_inputs_jlong)?;
    self_rptr.set_max_collateral_inputs(max_collateral_inputs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateMaxCollateralInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.max_collateral_inputs();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolParamUpdateNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ProtocolParamUpdate::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProtocolVersion::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProtocolVersion::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProtocolVersion::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionMajor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = self_rptr.major();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionMinor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = self_rptr.minor();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_protocolVersionNew(env: JNIEnv, _: JObject, major_jlong: jlong, minor_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let major = u32::try_from_jlong(major_jlong)?;
    let minor = u32::try_from_jlong(minor_jlong)?;
    let result = ProtocolVersion::new(major, minor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = PublicKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let result = self_rptr.to_bech32();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let result = self_rptr.as_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PublicKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyVerify(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_jarray: jbyteArray, signature_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let signature_jrptr = signature_ptr.rptr(&env)?;
    let signature = signature_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = self_rptr.verify(&data, signature);
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let result = self_rptr.hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PublicKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PublicKeys::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeysSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKeys>()?;
    let result = self_rptr.size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKeys>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_publicKeysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKeys>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<PublicKey>()?;
    self_rptr.add(key);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Redeemer::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Redeemer::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Redeemer::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTag(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.tag();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.index();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemer>()?;
    let result = self_rptr.ex_units();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerNew(env: JNIEnv, _: JObject, tag_ptr: JRPtr, index_ptr: JRPtr, data_ptr: JRPtr, ex_units_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tag_jrptr = tag_ptr.rptr(&env)?;
    let tag = tag_jrptr.typed_ref::<RedeemerTag>()?;
    let index_jrptr = index_ptr.rptr(&env)?;
    let index = index_jrptr.typed_ref::<BigNum>()?;
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<PlutusData>()?;
    let ex_units_jrptr = ex_units_ptr.rptr(&env)?;
    let ex_units = ex_units_jrptr.typed_ref::<ExUnits>()?;
    let result = Redeemer::new(tag, index, data, ex_units);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RedeemerTag>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = RedeemerTag::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RedeemerTag>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = RedeemerTag::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RedeemerTag>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = RedeemerTag::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagNewSpend(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_spend();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagNewMint(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_mint();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagNewCert(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagNewReward(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_reward();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemerTagKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RedeemerTag>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Redeemers::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Redeemers::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Redeemers::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Redeemers::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Redeemer>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_redeemersTotalExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Redeemers>()?;
    let result = self_rptr.total_ex_units().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Relay::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Relay::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Relay::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayNewSingleHostAddr(env: JNIEnv, _: JObject, single_host_addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let single_host_addr_jrptr = single_host_addr_ptr.rptr(&env)?;
    let single_host_addr = single_host_addr_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = Relay::new_single_host_addr(single_host_addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayNewSingleHostName(env: JNIEnv, _: JObject, single_host_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let single_host_name_jrptr = single_host_name_ptr.rptr(&env)?;
    let single_host_name = single_host_name_jrptr.typed_ref::<SingleHostName>()?;
    let result = Relay::new_single_host_name(single_host_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayNewMultiHostName(env: JNIEnv, _: JObject, multi_host_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let multi_host_name_jrptr = multi_host_name_ptr.rptr(&env)?;
    let multi_host_name = multi_host_name_jrptr.typed_ref::<MultiHostName>()?;
    let result = Relay::new_multi_host_name(multi_host_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayAsSingleHostAddr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.as_single_host_addr();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayAsSingleHostName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.as_single_host_name();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relayAsMultiHostName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relay>()?;
    let result = self_rptr.as_multi_host_name();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Relays::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Relays::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Relays::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Relays::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_relaysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Relays>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Relay>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<StakeCredential>()?;
    let result = RewardAddress::new(network, payment);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddress>()?;
    let result = self_rptr.payment_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = RewardAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = RewardAddresses::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = RewardAddresses::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = RewardAddresses::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RewardAddresses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_rewardAddressesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddresses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<RewardAddress>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAll>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptAll::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAll>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptAll::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAll>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptAll::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAll>()?;
    let result = self_rptr.native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAllNew(env: JNIEnv, _: JObject, native_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let native_scripts_jrptr = native_scripts_ptr.rptr(&env)?;
    let native_scripts = native_scripts_jrptr.typed_ref::<NativeScripts>()?;
    let result = ScriptAll::new(native_scripts);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAny>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptAny::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAny>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptAny::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAny>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptAny::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptAny>()?;
    let result = self_rptr.native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptAnyNew(env: JNIEnv, _: JObject, native_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let native_scripts_jrptr = native_scripts_ptr.rptr(&env)?;
    let native_scripts = native_scripts_jrptr.typed_ref::<NativeScripts>()?;
    let result = ScriptAny::new(native_scripts);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptDataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptDataHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptDataHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = ScriptDataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptDataHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptDataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = ScriptDataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = ScriptHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = ScriptHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ScriptHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptHashes>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<ScriptHash>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptNOfK::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptNOfK::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptNOfK::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKN(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = self_rptr.n();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptNOfK>()?;
    let result = self_rptr.native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptNOfKNew(env: JNIEnv, _: JObject, n_jlong: jlong, native_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let n = u32::try_from_jlong(n_jlong)?;
    let native_scripts_jrptr = native_scripts_ptr.rptr(&env)?;
    let native_scripts = native_scripts_jrptr.typed_ref::<NativeScripts>()?;
    let result = ScriptNOfK::new(n, native_scripts);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptPubkey>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptPubkey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptPubkey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptPubkey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptPubkey>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptPubkey::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyAddrKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptPubkey>()?;
    let result = self_rptr.addr_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptPubkeyNew(env: JNIEnv, _: JObject, addr_keyhash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_keyhash_jrptr = addr_keyhash_ptr.rptr(&env)?;
    let addr_keyhash = addr_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = ScriptPubkey::new(addr_keyhash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptRef::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptRef::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptRef::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefNewNativeScript(env: JNIEnv, _: JObject, native_script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let native_script_jrptr = native_script_ptr.rptr(&env)?;
    let native_script = native_script_jrptr.typed_ref::<NativeScript>()?;
    let result = ScriptRef::new_native_script(native_script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefNewPlutusScript(env: JNIEnv, _: JObject, plutus_script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let plutus_script_jrptr = plutus_script_ptr.rptr(&env)?;
    let plutus_script = plutus_script_jrptr.typed_ref::<PlutusScript>()?;
    let result = ScriptRef::new_plutus_script(plutus_script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefIsNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.is_native_script();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefIsPlutusScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.is_plutus_script();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.native_script();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_scriptRefPlutusScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.plutus_script();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = SingleHostAddr::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = SingleHostAddr::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = SingleHostAddr::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrPort(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.port();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrIpv4(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.ipv4();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrIpv6(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostAddr>()?;
    let result = self_rptr.ipv6();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = SingleHostAddr::new(None, None, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithPort(env: JNIEnv, _: JObject, port_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let result = SingleHostAddr::new(Some(port), None, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithIpv4(env: JNIEnv, _: JObject, ipv4_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ipv4 = ipv4_ptr.rptr(&env)?.typed_ref::<Ipv4>()?.clone();
    let result = SingleHostAddr::new(None, Some(ipv4), None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithPortIpv4(env: JNIEnv, _: JObject, port_jlong: jlong, ipv4_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let ipv4 = ipv4_ptr.rptr(&env)?.typed_ref::<Ipv4>()?.clone();
    let result = SingleHostAddr::new(Some(port), Some(ipv4), None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithIpv6(env: JNIEnv, _: JObject, ipv6_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ipv6 = ipv6_ptr.rptr(&env)?.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(None, None, Some(ipv6));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithPortIpv6(env: JNIEnv, _: JObject, port_jlong: jlong, ipv6_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let ipv6 = ipv6_ptr.rptr(&env)?.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(Some(port), None, Some(ipv6));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithIpv4Ipv6(env: JNIEnv, _: JObject, ipv4_ptr: JRPtr, ipv6_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ipv4 = ipv4_ptr.rptr(&env)?.typed_ref::<Ipv4>()?.clone();
    let ipv6 = ipv6_ptr.rptr(&env)?.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(None, Some(ipv4), Some(ipv6));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostAddrNewWithPortIpv4Ipv6(env: JNIEnv, _: JObject, port_jlong: jlong, ipv4_ptr: JRPtr, ipv6_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let ipv4 = ipv4_ptr.rptr(&env)?.typed_ref::<Ipv4>()?.clone();
    let ipv6 = ipv6_ptr.rptr(&env)?.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(Some(port), Some(ipv4), Some(ipv6));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostName>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = SingleHostName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostName>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = SingleHostName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostName>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = SingleHostName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNamePort(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostName>()?;
    let result = self_rptr.port();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameDnsName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<SingleHostName>()?;
    let result = self_rptr.dns_name();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameNew(env: JNIEnv, _: JObject, dns_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let dns_name_jrptr = dns_name_ptr.rptr(&env)?;
    let dns_name = dns_name_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = SingleHostName::new(None, dns_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_singleHostNameNewWithPort(env: JNIEnv, _: JObject, port_jlong: jlong, dns_name_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let dns_name_jrptr = dns_name_ptr.rptr(&env)?;
    let dns_name = dns_name_jrptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = SingleHostName::new(Some(port), dns_name);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialFromKeyhash(env: JNIEnv, _: JObject, hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = StakeCredential::from_keyhash(hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialFromScripthash(env: JNIEnv, _: JObject, hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = StakeCredential::from_scripthash(hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialToKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.to_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialToScripthash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.to_scripthash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeCredential::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeCredential::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredential>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeCredential::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeCredentials::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeCredentials::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeCredentials::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = StakeCredentials::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeCredentialsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeCredentials>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<StakeCredential>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.pool_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<StakeCredential>()?;
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = StakeDelegation::new(stake_credential, pool_keyhash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeDeregistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeDeregistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeDeregistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeDeregistrationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<StakeCredential>()?;
    let result = StakeDeregistration::new(stake_credential);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeRegistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeRegistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeRegistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stakeRegistrationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<StakeCredential>()?;
    let result = StakeRegistration::new(stake_credential);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stringsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Strings::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stringsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Strings>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stringsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Strings>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_stringsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Strings>()?;
    let elem = elem_str.string(&env)?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TimelockExpiry::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TimelockExpiry::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TimelockExpiry::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpirySlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = self_rptr.slot().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpirySlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockExpiry>()?;
    let result = self_rptr.slot_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryNew(env: JNIEnv, _: JObject, slot_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let slot = u32::try_from_jlong(slot_jlong)?;
    let result = TimelockExpiry::new(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockExpiryNewTimelockexpiry(env: JNIEnv, _: JObject, slot_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let slot_jrptr = slot_ptr.rptr(&env)?;
    let slot = slot_jrptr.typed_ref::<BigNum>()?;
    let result = TimelockExpiry::new_timelockexpiry(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockStart>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TimelockStart::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockStart>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TimelockStart::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockStart>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TimelockStart::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartSlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockStart>()?;
    let result = self_rptr.slot().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartSlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TimelockStart>()?;
    let result = self_rptr.slot_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartNew(env: JNIEnv, _: JObject, slot_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let slot = u32::try_from_jlong(slot_jlong)?;
    let result = TimelockStart::new(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_timelockStartNewTimelockstart(env: JNIEnv, _: JObject, slot_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let slot_jrptr = slot_ptr.rptr(&env)?;
    let slot = slot_jrptr.typed_ref::<BigNum>()?;
    let result = TimelockStart::new_timelockstart(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Transaction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Transaction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Transaction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.body();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.witness_set();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.is_valid();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.auxiliary_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionSetIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr, valid_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let valid = valid_jboolean.into_bool();
    self_rptr.set_is_valid(valid);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionNew(env: JNIEnv, _: JObject, body_ptr: JRPtr, witness_set_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let body_jrptr = body_ptr.rptr(&env)?;
    let body = body_jrptr.typed_ref::<TransactionBody>()?;
    let witness_set_jrptr = witness_set_ptr.rptr(&env)?;
    let witness_set = witness_set_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = Transaction::new(body, witness_set, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionNewWithAuxiliaryData(env: JNIEnv, _: JObject, body_ptr: JRPtr, witness_set_ptr: JRPtr, auxiliary_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let body_jrptr = body_ptr.rptr(&env)?;
    let body = body_jrptr.typed_ref::<TransactionBody>()?;
    let witness_set_jrptr = witness_set_ptr.rptr(&env)?;
    let witness_set = witness_set_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let auxiliary_data = auxiliary_data_ptr.rptr(&env)?.typed_ref::<AuxiliaryData>()?.clone();
    let result = Transaction::new(body, witness_set, Some(auxiliary_data));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBatchLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBatch>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBatchGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBatch>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBatchListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBatchList>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBatchListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBatchList>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionBodies::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionBodies::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionBodies::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionBodies::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodiesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBodies>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionBody>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionBody::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionBody::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionBody::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyOutputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.outputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyFee(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.fee();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.ttl().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyTtlBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.ttl_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let ttl_jrptr = ttl_ptr.rptr(&env)?;
    let ttl = ttl_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_ttl(ttl);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyRemoveTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    self_rptr.remove_ttl();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr, certs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let certs_jrptr = certs_ptr.rptr(&env)?;
    let certs = certs_jrptr.typed_ref::<Certificates>()?;
    self_rptr.set_certs(certs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.certs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr, withdrawals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<Withdrawals>()?;
    self_rptr.set_withdrawals(withdrawals);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.withdrawals();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetUpdate(env: JNIEnv, _: JObject, self_ptr: JRPtr, update_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let update_jrptr = update_ptr.rptr(&env)?;
    let update = update_jrptr.typed_ref::<Update>()?;
    self_rptr.set_update(update);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyUpdate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.update();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetAuxiliaryDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, auxiliary_data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let auxiliary_data_hash_jrptr = auxiliary_data_hash_ptr.rptr(&env)?;
    let auxiliary_data_hash = auxiliary_data_hash_jrptr.typed_ref::<AuxiliaryDataHash>()?;
    self_rptr.set_auxiliary_data_hash(auxiliary_data_hash);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyAuxiliaryDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.auxiliary_data_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let validity_start_interval = u32::try_from_jlong(validity_start_interval_jlong)?;
    self_rptr.set_validity_start_interval(validity_start_interval);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let validity_start_interval = validity_start_interval_ptr.rptr(&env)?.typed_ref::<BigNum>()?.clone();
    self_rptr.set_validity_start_interval_bignum(validity_start_interval);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.validity_start_interval_bignum();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.validity_start_interval().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<Mint>()?;
    self_rptr.set_mint(mint);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyMint(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.mint();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyMultiassets(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.multiassets();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, reference_inputs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let reference_inputs_jrptr = reference_inputs_ptr.rptr(&env)?;
    let reference_inputs = reference_inputs_jrptr.typed_ref::<TransactionInputs>()?;
    self_rptr.set_reference_inputs(reference_inputs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.reference_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let script_data_hash_jrptr = script_data_hash_ptr.rptr(&env)?;
    let script_data_hash = script_data_hash_jrptr.typed_ref::<ScriptDataHash>()?;
    self_rptr.set_script_data_hash(script_data_hash);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.script_data_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let collateral_jrptr = collateral_ptr.rptr(&env)?;
    let collateral = collateral_jrptr.typed_ref::<TransactionInputs>()?;
    self_rptr.set_collateral(collateral);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.collateral();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, required_signers_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let required_signers_jrptr = required_signers_ptr.rptr(&env)?;
    let required_signers = required_signers_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    self_rptr.set_required_signers(required_signers);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.required_signers();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr, network_id_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let network_id_jrptr = network_id_ptr.rptr(&env)?;
    let network_id = network_id_jrptr.typed_ref::<NetworkId>()?;
    self_rptr.set_network_id(network_id);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.network_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let collateral_return_jrptr = collateral_return_ptr.rptr(&env)?;
    let collateral_return = collateral_return_jrptr.typed_ref::<TransactionOutput>()?;
    self_rptr.set_collateral_return(collateral_return);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.collateral_return();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodySetTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let total_collateral_jrptr = total_collateral_ptr.rptr(&env)?;
    let total_collateral = total_collateral_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_total_collateral(total_collateral);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.total_collateral();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyNew(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionInputs>()?;
    let outputs_jrptr = outputs_ptr.rptr(&env)?;
    let outputs = outputs_jrptr.typed_ref::<TransactionOutputs>()?;
    let fee_jrptr = fee_ptr.rptr(&env)?;
    let fee = fee_jrptr.typed_ref::<BigNum>()?;
    let result = TransactionBody::new(inputs, outputs, fee, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyNewWithTtl(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr, ttl_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionInputs>()?;
    let outputs_jrptr = outputs_ptr.rptr(&env)?;
    let outputs = outputs_jrptr.typed_ref::<TransactionOutputs>()?;
    let fee_jrptr = fee_ptr.rptr(&env)?;
    let fee = fee_jrptr.typed_ref::<BigNum>()?;
    let ttl = u32::try_from_jlong(ttl_jlong)?;
    let result = TransactionBody::new(inputs, outputs, fee, Some(ttl));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBodyNewTxBody(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionInputs>()?;
    let outputs_jrptr = outputs_ptr.rptr(&env)?;
    let outputs = outputs_jrptr.typed_ref::<TransactionOutputs>()?;
    let fee_jrptr = fee_ptr.rptr(&env)?;
    let fee = fee_jrptr.typed_ref::<BigNum>()?;
    let result = TransactionBody::new_tx_body(inputs, outputs, fee);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddInputsFrom(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr, strategy_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let strategy = strategy_jint.to_enum()?;
    self_rptr.add_inputs_from(inputs, strategy).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TxInputsBuilder>()?;
    self_rptr.set_inputs(inputs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let collateral_jrptr = collateral_ptr.rptr(&env)?;
    let collateral = collateral_jrptr.typed_ref::<TxInputsBuilder>()?;
    self_rptr.set_collateral(collateral);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let collateral_return_jrptr = collateral_return_ptr.rptr(&env)?;
    let collateral_return = collateral_return_jrptr.typed_ref::<TransactionOutput>()?;
    self_rptr.set_collateral_return(collateral_return);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetCollateralReturnAndTotal(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let collateral_return_jrptr = collateral_return_ptr.rptr(&env)?;
    let collateral_return = collateral_return_jrptr.typed_ref::<TransactionOutput>()?;
    self_rptr.set_collateral_return_and_total(collateral_return).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let total_collateral_jrptr = total_collateral_ptr.rptr(&env)?;
    let total_collateral = total_collateral_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_total_collateral(total_collateral);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetTotalCollateralAndReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr, return_address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let total_collateral_jrptr = total_collateral_ptr.rptr(&env)?;
    let total_collateral = total_collateral_jrptr.typed_ref::<BigNum>()?;
    let return_address_jrptr = return_address_ptr.rptr(&env)?;
    let return_address = return_address_jrptr.typed_ref::<Address>()?;
    self_rptr.set_total_collateral_and_return(total_collateral, return_address).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddReferenceInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, reference_input_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let reference_input_jrptr = reference_input_ptr.rptr(&env)?;
    let reference_input = reference_input_jrptr.typed_ref::<TransactionInput>()?;
    self_rptr.add_reference_input(reference_input);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddKeyInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_key_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_script_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddNativeScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<NativeScript>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_native_script_input(script, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddPlutusScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, witness_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_plutus_script_input(witness, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddBootstrapInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ByronAddress>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_bootstrap_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_input(address, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderCountMissingInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.count_missing_input_scripts();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddRequiredNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let scripts_jrptr = scripts_ptr.rptr(&env)?;
    let scripts = scripts_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.add_required_native_input_scripts(scripts);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddRequiredPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let scripts_jrptr = scripts_ptr.rptr(&env)?;
    let scripts = scripts_jrptr.typed_ref::<PlutusWitnesses>()?;
    let result = self_rptr.add_required_plutus_input_scripts(scripts);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_native_input_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_plutus_input_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderFeeForInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.fee_for_input(address, input, amount).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let output_jrptr = output_ptr.rptr(&env)?;
    let output = output_jrptr.typed_ref::<TransactionOutput>()?;
    self_rptr.add_output(output).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderFeeForOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let output_jrptr = output_ptr.rptr(&env)?;
    let output = output_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.fee_for_output(output).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetFee(env: JNIEnv, _: JObject, self_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let fee_jrptr = fee_ptr.rptr(&env)?;
    let fee = fee_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_fee(fee);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let ttl = u32::try_from_jlong(ttl_jlong)?;
    self_rptr.set_ttl(ttl);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetTtlBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let ttl_jrptr = ttl_ptr.rptr(&env)?;
    let ttl = ttl_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_ttl_bignum(ttl);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let validity_start_interval = u32::try_from_jlong(validity_start_interval_jlong)?;
    self_rptr.set_validity_start_interval(validity_start_interval);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let validity_start_interval = validity_start_interval_ptr.rptr(&env)?.typed_ref::<BigNum>()?.clone();
    self_rptr.set_validity_start_interval_bignum(validity_start_interval);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr, certs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let certs_jrptr = certs_ptr.rptr(&env)?;
    let certs = certs_jrptr.typed_ref::<Certificates>()?;
    self_rptr.set_certs(certs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr, withdrawals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<Withdrawals>()?;
    self_rptr.set_withdrawals(withdrawals);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_auxiliary_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr, auxiliary_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let auxiliary_data_jrptr = auxiliary_data_ptr.rptr(&env)?;
    let auxiliary_data = auxiliary_data_jrptr.typed_ref::<AuxiliaryData>()?;
    self_rptr.set_auxiliary_data(auxiliary_data);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr, metadata_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let metadata_jrptr = metadata_ptr.rptr(&env)?;
    let metadata = metadata_jrptr.typed_ref::<GeneralTransactionMetadata>()?;
    self_rptr.set_metadata(metadata);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddMetadatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<BigNum>()?;
    let val_jrptr = val_ptr.rptr(&env)?;
    let val = val_jrptr.typed_ref::<TransactionMetadatum>()?;
    self_rptr.add_metadatum(key, val);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddJsonMetadatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<BigNum>()?;
    let val = val_str.string(&env)?;
    self_rptr.add_json_metadatum(key, val).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddJsonMetadatumWithSchema(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<BigNum>()?;
    let val = val_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    self_rptr.add_json_metadatum_with_schema(key, val, schema).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetMintBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_builder_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let mint_builder_jrptr = mint_builder_ptr.rptr(&env)?;
    let mint_builder = mint_builder_jrptr.typed_ref::<MintBuilder>()?;
    self_rptr.set_mint_builder(mint_builder);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetMintBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_mint_builder();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, mint_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<Mint>()?;
    let mint_scripts_jrptr = mint_scripts_ptr.rptr(&env)?;
    let mint_scripts = mint_scripts_jrptr.typed_ref::<NativeScripts>()?;
    self_rptr.set_mint(mint, mint_scripts).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_mint();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetMintScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_mint_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetMintAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, mint_assets_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let mint_assets_jrptr = mint_assets_ptr.rptr(&env)?;
    let mint_assets = mint_assets_jrptr.typed_ref::<MintAssets>()?;
    self_rptr.set_mint_asset(policy_script, mint_assets);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddMintAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount = amount_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    self_rptr.add_mint_asset(policy_script, asset_name, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddMintAssetAndOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr, output_builder_ptr: JRPtr, output_coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount = amount_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    let output_builder_jrptr = output_builder_ptr.rptr(&env)?;
    let output_builder = output_builder_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let output_coin_jrptr = output_coin_ptr.rptr(&env)?;
    let output_coin = output_coin_jrptr.typed_ref::<BigNum>()?;
    self_rptr.add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddMintAssetAndOutputMinRequiredCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr, output_builder_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount = amount_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    let output_builder_jrptr = output_builder_ptr.rptr(&env)?;
    let output_builder = output_builder_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    self_rptr.add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderNew(env: JNIEnv, _: JObject, cfg_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let cfg_jrptr = cfg_ptr.rptr(&env)?;
    let cfg = cfg_jrptr.typed_ref::<TransactionBuilderConfig>()?;
    let result = TransactionBuilder::new(cfg);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_reference_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetExplicitInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_explicit_input().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetImplicitInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_implicit_input().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetTotalInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_total_input().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetTotalOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_total_output().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetExplicitOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_explicit_output().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_deposit().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderGetFeeIfSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_fee_if_set();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddChangeIfNeeded(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.add_change_if_needed(address).into_result()?;
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderCalcScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let cost_models_jrptr = cost_models_ptr.rptr(&env)?;
    let cost_models = cost_models_jrptr.typed_ref::<Costmdls>()?;
    self_rptr.calc_script_data_hash(cost_models).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderSetScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ScriptDataHash>()?;
    self_rptr.set_script_data_hash(hash);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderRemoveScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_script_data_hash();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderAddRequiredSigner(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Ed25519KeyHash>()?;
    self_rptr.add_required_signer(key);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderFullSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.full_size().into_result()?;
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderOutputSizes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.output_sizes();
    usize_array_to_base64(&result).jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.build().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderBuildTx(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.build_tx().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderBuildTxUnsafe(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.build_tx_unsafe().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderMinFee(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.min_fee().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}




#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionBuilderConfigBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderFeeAlgo(env: JNIEnv, _: JObject, self_ptr: JRPtr, fee_algo_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let fee_algo_jrptr = fee_algo_ptr.rptr(&env)?;
    let fee_algo = fee_algo_jrptr.typed_ref::<LinearFee>()?;
    let result = self_rptr.fee_algo(fee_algo);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderCoinsPerUtxoWord(env: JNIEnv, _: JObject, self_ptr: JRPtr, coins_per_utxo_word_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let coins_per_utxo_word_jrptr = coins_per_utxo_word_ptr.rptr(&env)?;
    let coins_per_utxo_word = coins_per_utxo_word_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.coins_per_utxo_word(coins_per_utxo_word);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderCoinsPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, coins_per_utxo_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let coins_per_utxo_byte_jrptr = coins_per_utxo_byte_ptr.rptr(&env)?;
    let coins_per_utxo_byte = coins_per_utxo_byte_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.coins_per_utxo_byte(coins_per_utxo_byte);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderExUnitPrices(env: JNIEnv, _: JObject, self_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let ex_unit_prices_jrptr = ex_unit_prices_ptr.rptr(&env)?;
    let ex_unit_prices = ex_unit_prices_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = self_rptr.ex_unit_prices(ex_unit_prices);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderPoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.pool_deposit(pool_deposit);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.key_deposit(key_deposit);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_value_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let max_value_size = u32::try_from_jlong(max_value_size_jlong)?;
    let result = self_rptr.max_value_size(max_value_size);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let max_tx_size = u32::try_from_jlong(max_tx_size_jlong)?;
    let result = self_rptr.max_tx_size(max_tx_size);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderPreferPureChange(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefer_pure_change_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let prefer_pure_change = prefer_pure_change_jboolean.into_bool();
    let result = self_rptr.prefer_pure_change(prefer_pure_change);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionBuilderConfigBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let result = self_rptr.build().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = TransactionHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = TransactionHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionInput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionInput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionInput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputTransactionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.transaction_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.index();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputNew(env: JNIEnv, _: JObject, transaction_id_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let transaction_id_jrptr = transaction_id_ptr.rptr(&env)?;
    let transaction_id = transaction_id_jrptr.typed_ref::<TransactionHash>()?;
    let index = u32::try_from_jlong(index_jlong)?;
    let result = TransactionInput::new(transaction_id, index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionInputs::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionInputs::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionInputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionInputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionInput>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionInputsToOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let result = self_rptr.to_option();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatum::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionMetadatum::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumNewMap(env: JNIEnv, _: JObject, map_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let map_jrptr = map_ptr.rptr(&env)?;
    let map = map_jrptr.typed_ref::<MetadataMap>()?;
    let result = TransactionMetadatum::new_map(map);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumNewList(env: JNIEnv, _: JObject, list_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let list_jrptr = list_ptr.rptr(&env)?;
    let list = list_jrptr.typed_ref::<MetadataList>()?;
    let result = TransactionMetadatum::new_list(list);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumNewInt(env: JNIEnv, _: JObject, int_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let int_value_jrptr = int_value_ptr.rptr(&env)?;
    let int_value = int_value_jrptr.typed_ref::<Int>()?;
    let result = TransactionMetadatum::new_int(int_value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumNewBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatum::new_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumNewText(env: JNIEnv, _: JObject, text_str: JString) -> jobject {
  handle_exception_result(|| { 
    let text = text_str.string(&env)?;
    let result = TransactionMetadatum::new_text(text).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumAsMap(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.as_map().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumAsList(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.as_list().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumAsInt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.as_int().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.as_bytes().into_result()?;
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumAsText(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.as_text().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatumLabels::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionMetadatumLabels::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionMetadatumLabels::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatumLabels>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionMetadatumLabelsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionMetadatumLabels>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<BigNum>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionOutput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionOutput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionOutput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmount(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.amount();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.data_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.plutus_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.script_ref();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputSetScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ref_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let script_ref_jrptr = script_ref_ptr.rptr(&env)?;
    let script_ref = script_ref_jrptr.typed_ref::<ScriptRef>()?;
    self_rptr.set_script_ref(script_ref);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<PlutusData>()?;
    self_rptr.set_plutus_data(data);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputSetDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let data_hash_jrptr = data_hash_ptr.rptr(&env)?;
    let data_hash = data_hash_jrptr.typed_ref::<DataHash>()?;
    self_rptr.set_data_hash(data_hash);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputHasPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_plutus_data();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputHasDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_data_hash();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputHasScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_script_ref();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputNew(env: JNIEnv, _: JObject, address_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    let result = TransactionOutput::new(address, amount);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderWithValue(env: JNIEnv, _: JObject, self_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.with_value(amount);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderWithCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.with_coin(coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderWithCoinAndAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    let result = self_rptr.with_coin_and_asset(coin, multiasset);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderWithAssetAndMinRequiredCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, multiasset_ptr: JRPtr, coins_per_utxo_word_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    let coins_per_utxo_word_jrptr = coins_per_utxo_word_ptr.rptr(&env)?;
    let coins_per_utxo_word = coins_per_utxo_word_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.with_asset_and_min_required_coin(multiasset, coins_per_utxo_word).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(env: JNIEnv, _: JObject, self_ptr: JRPtr, multiasset_ptr: JRPtr, data_cost_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    let data_cost_jrptr = data_cost_ptr.rptr(&env)?;
    let data_cost = data_cost_jrptr.typed_ref::<DataCost>()?;
    let result = self_rptr.with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputAmountBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let result = self_rptr.build().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionOutputBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderWithAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.with_address(address);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderWithDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputBuilder>()?;
    let data_hash_jrptr = data_hash_ptr.rptr(&env)?;
    let data_hash = data_hash_jrptr.typed_ref::<DataHash>()?;
    let result = self_rptr.with_data_hash(data_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderWithPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputBuilder>()?;
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<PlutusData>()?;
    let result = self_rptr.with_plutus_data(data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderWithScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ref_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputBuilder>()?;
    let script_ref_jrptr = script_ref_ptr.rptr(&env)?;
    let script_ref = script_ref_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.with_script_ref(script_ref);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputBuilderNext(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputBuilder>()?;
    let result = self_rptr.next().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionOutputs::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionOutputs::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionOutputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionOutputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionOutputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutputs>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionOutput>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionUnspentOutput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionUnspentOutput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionUnspentOutput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputNew(env: JNIEnv, _: JObject, input_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let output_jrptr = output_ptr.rptr(&env)?;
    let output = output_jrptr.typed_ref::<TransactionOutput>()?;
    let result = TransactionUnspentOutput::new(input, output);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_rptr.input();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_rptr.output();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionUnspentOutputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionUnspentOutputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionUnspentOutputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionUnspentOutput>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionWitnessSet::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionWitnessSet::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionWitnessSet::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetVkeys(env: JNIEnv, _: JObject, self_ptr: JRPtr, vkeys_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let vkeys_jrptr = vkeys_ptr.rptr(&env)?;
    let vkeys = vkeys_jrptr.typed_ref::<Vkeywitnesses>()?;
    self_rptr.set_vkeys(vkeys);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetVkeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.vkeys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, native_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let native_scripts_jrptr = native_scripts_ptr.rptr(&env)?;
    let native_scripts = native_scripts_jrptr.typed_ref::<NativeScripts>()?;
    self_rptr.set_native_scripts(native_scripts);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetBootstraps(env: JNIEnv, _: JObject, self_ptr: JRPtr, bootstraps_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let bootstraps_jrptr = bootstraps_ptr.rptr(&env)?;
    let bootstraps = bootstraps_jrptr.typed_ref::<BootstrapWitnesses>()?;
    self_rptr.set_bootstraps(bootstraps);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetBootstraps(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.bootstraps();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let plutus_scripts_jrptr = plutus_scripts_ptr.rptr(&env)?;
    let plutus_scripts = plutus_scripts_jrptr.typed_ref::<PlutusScripts>()?;
    self_rptr.set_plutus_scripts(plutus_scripts);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.plutus_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let plutus_data_jrptr = plutus_data_ptr.rptr(&env)?;
    let plutus_data = plutus_data_jrptr.typed_ref::<PlutusList>()?;
    self_rptr.set_plutus_data(plutus_data);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.plutus_data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetSetRedeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr, redeemers_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let redeemers_jrptr = redeemers_ptr.rptr(&env)?;
    let redeemers = redeemers_jrptr.typed_ref::<Redeemers>()?;
    self_rptr.set_redeemers(redeemers);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetRedeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_rptr.redeemers();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionWitnessSet::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionWitnessSets::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionWitnessSets::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionWitnessSets::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionWitnessSets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_transactionWitnessSetsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionWitnessSets>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionWitnessSet>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txBuilderConstantsPlutusDefaultCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_default_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txBuilderConstantsPlutusAlonzoCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_alonzo_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txBuilderConstantsPlutusVasilCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_vasil_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxInputsBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddKeyInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_key_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_script_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddNativeScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<NativeScript>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_native_script_input(script, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddPlutusScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, witness_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_plutus_script_input(witness, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddBootstrapInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ByronAddress>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_bootstrap_input(hash, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_input(address, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderCountMissingInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.count_missing_input_scripts();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddRequiredNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let scripts_jrptr = scripts_ptr.rptr(&env)?;
    let scripts = scripts_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.add_required_native_input_scripts(scripts);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddRequiredPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, scripts_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let scripts_jrptr = scripts_ptr.rptr(&env)?;
    let scripts = scripts_jrptr.typed_ref::<PlutusWitnesses>()?;
    let result = self_rptr.add_required_plutus_input_scripts(scripts);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddRequiredScriptInputWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_with_wit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let inputs_with_wit_jrptr = inputs_with_wit_ptr.rptr(&env)?;
    let inputs_with_wit = inputs_with_wit_jrptr.typed_ref::<InputsWithScriptWitness>()?;
    let result = self_rptr.add_required_script_input_witnesses(inputs_with_wit);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderGetNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.get_native_input_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderGetPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.get_plutus_input_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddRequiredSigner(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Ed25519KeyHash>()?;
    self_rptr.add_required_signer(key);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderAddRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, keys_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let keys_jrptr = keys_ptr.rptr(&env)?;
    let keys = keys_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    self_rptr.add_required_signers(keys);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderTotalValue(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.total_value().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_txInputsBuilderInputsOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_rptr.inputs_option();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<URL>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = URL::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<URL>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = URL::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<URL>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = URL::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLNew(env: JNIEnv, _: JObject, url_str: JString) -> jobject {
  handle_exception_result(|| { 
    let url = url_str.string(&env)?;
    let result = URL::new(url).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_uRLUrl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<URL>()?;
    let result = self_rptr.url();
    result.jstring(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = UnitInterval::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = UnitInterval::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = UnitInterval::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalNumerator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.numerator();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalDenominator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.denominator();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_unitIntervalNew(env: JNIEnv, _: JObject, numerator_ptr: JRPtr, denominator_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let numerator_jrptr = numerator_ptr.rptr(&env)?;
    let numerator = numerator_jrptr.typed_ref::<BigNum>()?;
    let denominator_jrptr = denominator_ptr.rptr(&env)?;
    let denominator = denominator_jrptr.typed_ref::<BigNum>()?;
    let result = UnitInterval::new(numerator, denominator);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Update>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Update::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Update>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Update::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Update>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Update::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateProposedProtocolParameterUpdates(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Update>()?;
    let result = self_rptr.proposed_protocol_parameter_updates();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Update>()?;
    let result = self_rptr.epoch();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_updateNew(env: JNIEnv, _: JObject, proposed_protocol_parameter_updates_ptr: JRPtr, epoch_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let proposed_protocol_parameter_updates_jrptr = proposed_protocol_parameter_updates_ptr.rptr(&env)?;
    let proposed_protocol_parameter_updates = proposed_protocol_parameter_updates_jrptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let epoch = u32::try_from_jlong(epoch_jlong)?;
    let result = Update::new(proposed_protocol_parameter_updates, epoch);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFCert>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFCert>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VRFCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFCert>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VRFCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFCert>()?;
    let result = self_rptr.output();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertProof(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFCert>()?;
    let result = self_rptr.proof();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFCertNew(env: JNIEnv, _: JObject, output_jarray: jbyteArray, proof_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let output = env.convert_byte_array(output_jarray).into_result()?;
    let proof = env.convert_byte_array(proof_jarray).into_result()?;
    let result = VRFCert::new(output, proof).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFKeyHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFKeyHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFKeyHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = VRFKeyHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFKeyHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFKeyHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = VRFKeyHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFVKey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFVKey>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFVKey>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = VRFVKey::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VRFVKey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vRFVKeyFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = VRFVKey::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Value::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Value::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Value::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueNew(env: JNIEnv, _: JObject, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = Value::new(coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueNewFromAssets(env: JNIEnv, _: JObject, multiasset_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    let result = Value::new_from_assets(multiasset);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueNewWithAssets(env: JNIEnv, _: JObject, coin_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    let result = Value::new_with_assets(coin, multiasset);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueZero(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Value::zero();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.is_zero();
    (result as jboolean).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueSetCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_coin(coin);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.multiasset();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueSetMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let multiasset_jrptr = multiasset_ptr.rptr(&env)?;
    let multiasset = multiasset_jrptr.typed_ref::<MultiAsset>()?;
    self_rptr.set_multiasset(multiasset);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueCheckedAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let rhs_jrptr = rhs_ptr.rptr(&env)?;
    let rhs = rhs_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.checked_add(rhs).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueCheckedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.checked_sub(rhs_value).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueClampedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.clamped_sub(rhs_value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_valueCompare(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.compare(rhs_value);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkey>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkey>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkey>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkey::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyNew(env: JNIEnv, _: JObject, pk_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let pk_jrptr = pk_ptr.rptr(&env)?;
    let pk = pk_jrptr.typed_ref::<PublicKey>()?;
    let result = Vkey::new(pk);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeyPublicKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkey>()?;
    let result = self_rptr.public_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Vkeys::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeysLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeys>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeys>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeys>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Vkey>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkeywitness::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkeywitness::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkeywitness::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessNew(env: JNIEnv, _: JObject, vkey_ptr: JRPtr, signature_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let vkey_jrptr = vkey_ptr.rptr(&env)?;
    let vkey = vkey_jrptr.typed_ref::<Vkey>()?;
    let signature_jrptr = signature_ptr.rptr(&env)?;
    let signature = signature_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = Vkeywitness::new(vkey, signature);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.vkey();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessSignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.signature();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkeywitnesses::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkeywitnesses::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkeywitnesses::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Vkeywitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_vkeywitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Vkeywitness>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Withdrawals::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Withdrawals::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Withdrawals::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Withdrawals::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<RewardAddress>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.insert(key, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<RewardAddress>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_withdrawalsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Withdrawals>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_calculateExUnitsCeilCost(env: JNIEnv, _: JObject, ex_units_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ex_units_jrptr = ex_units_ptr.rptr(&env)?;
    let ex_units = ex_units_jrptr.typed_ref::<ExUnits>()?;
    let ex_unit_prices_jrptr = ex_unit_prices_ptr.rptr(&env)?;
    let ex_unit_prices = ex_unit_prices_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = calculate_ex_units_ceil_cost(ex_units, ex_unit_prices).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_createSendAll(env: JNIEnv, _: JObject, address_ptr: JRPtr, utxos_ptr: JRPtr, config_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let utxos_jrptr = utxos_ptr.rptr(&env)?;
    let utxos = utxos_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let config_jrptr = config_ptr.rptr(&env)?;
    let config = config_jrptr.typed_ref::<TransactionBuilderConfig>()?;
    let result = create_send_all(address, utxos, config).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_decodeArbitraryBytesFromMetadatum(env: JNIEnv, _: JObject, metadata_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let metadata_jrptr = metadata_ptr.rptr(&env)?;
    let metadata = metadata_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = decode_arbitrary_bytes_from_metadatum(metadata).into_result()?;
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_decodeMetadatumToJsonStr(env: JNIEnv, _: JObject, metadatum_ptr: JRPtr, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let metadatum_jrptr = metadatum_ptr.rptr(&env)?;
    let metadatum = metadatum_jrptr.typed_ref::<TransactionMetadatum>()?;
    let schema = schema_jint.to_enum()?;
    let result = decode_metadatum_to_json_str(metadatum, schema).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_decodePlutusDatumToJsonStr(env: JNIEnv, _: JObject, datum_ptr: JRPtr, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let datum_jrptr = datum_ptr.rptr(&env)?;
    let datum = datum_jrptr.typed_ref::<PlutusData>()?;
    let schema = schema_jint.to_enum()?;
    let result = decode_plutus_datum_to_json_str(datum, schema).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_decryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, data_str: JString) -> jobject {
  handle_exception_result(|| { 
    let password = password_str.string(&env)?;
    let data = data_str.string(&env)?;
    let result = decrypt_with_password(&password, &data).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_encodeArbitraryBytesAsMetadatum(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = encode_arbitrary_bytes_as_metadatum(&bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_encodeJsonStrToMetadatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    let result = encode_json_str_to_metadatum(json, schema).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_encodeJsonStrToNativeScript(env: JNIEnv, _: JObject, json_str: JString, self_xpub_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let self_xpub = self_xpub_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    let result = encode_json_str_to_native_script(&json, &self_xpub, schema).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_encodeJsonStrToPlutusDatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    let result = encode_json_str_to_plutus_datum(&json, schema).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_encryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, salt_str: JString, nonce_str: JString, data_str: JString) -> jobject {
  handle_exception_result(|| { 
    let password = password_str.string(&env)?;
    let salt = salt_str.string(&env)?;
    let nonce = nonce_str.string(&env)?;
    let data = data_str.string(&env)?;
    let result = encrypt_with_password(&password, &salt, &nonce, &data).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_getDeposit(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let txbody_jrptr = txbody_ptr.rptr(&env)?;
    let txbody = txbody_jrptr.typed_ref::<TransactionBody>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = get_deposit(txbody, pool_deposit, key_deposit).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_getImplicitInput(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let txbody_jrptr = txbody_ptr.rptr(&env)?;
    let txbody = txbody_jrptr.typed_ref::<TransactionBody>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = get_implicit_input(txbody, pool_deposit, key_deposit).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_hashAuxiliaryData(env: JNIEnv, _: JObject, auxiliary_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let auxiliary_data_jrptr = auxiliary_data_ptr.rptr(&env)?;
    let auxiliary_data = auxiliary_data_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = hash_auxiliary_data(auxiliary_data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_hashPlutusData(env: JNIEnv, _: JObject, plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let plutus_data_jrptr = plutus_data_ptr.rptr(&env)?;
    let plutus_data = plutus_data_jrptr.typed_ref::<PlutusData>()?;
    let result = hash_plutus_data(plutus_data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_hashScriptData(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let redeemers_jrptr = redeemers_ptr.rptr(&env)?;
    let redeemers = redeemers_jrptr.typed_ref::<Redeemers>()?;
    let cost_models_jrptr = cost_models_ptr.rptr(&env)?;
    let cost_models = cost_models_jrptr.typed_ref::<Costmdls>()?;
    let result = hash_script_data(redeemers, cost_models, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_hashScriptDataWithDatums(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr, datums_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let redeemers_jrptr = redeemers_ptr.rptr(&env)?;
    let redeemers = redeemers_jrptr.typed_ref::<Redeemers>()?;
    let cost_models_jrptr = cost_models_ptr.rptr(&env)?;
    let cost_models = cost_models_jrptr.typed_ref::<Costmdls>()?;
    let datums = datums_ptr.rptr(&env)?.typed_ref::<PlutusList>()?.clone();
    let result = hash_script_data(redeemers, cost_models, Some(datums));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_hashTransaction(env: JNIEnv, _: JObject, tx_body_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_body_jrptr = tx_body_ptr.rptr(&env)?;
    let tx_body = tx_body_jrptr.typed_ref::<TransactionBody>()?;
    let result = hash_transaction(tx_body);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_makeDaedalusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_body_hash_jrptr = tx_body_hash_ptr.rptr(&env)?;
    let tx_body_hash = tx_body_hash_jrptr.typed_ref::<TransactionHash>()?;
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<ByronAddress>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = make_daedalus_bootstrap_witness(tx_body_hash, addr, key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_makeIcarusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_body_hash_jrptr = tx_body_hash_ptr.rptr(&env)?;
    let tx_body_hash = tx_body_hash_jrptr.typed_ref::<TransactionHash>()?;
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<ByronAddress>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<Bip32PrivateKey>()?;
    let result = make_icarus_bootstrap_witness(tx_body_hash, addr, key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_makeVkeyWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, sk_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_body_hash_jrptr = tx_body_hash_ptr.rptr(&env)?;
    let tx_body_hash = tx_body_hash_jrptr.typed_ref::<TransactionHash>()?;
    let sk_jrptr = sk_ptr.rptr(&env)?;
    let sk = sk_jrptr.typed_ref::<PrivateKey>()?;
    let result = make_vkey_witness(tx_body_hash, sk);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_minAdaForOutput(env: JNIEnv, _: JObject, output_ptr: JRPtr, data_cost_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let output_jrptr = output_ptr.rptr(&env)?;
    let output = output_jrptr.typed_ref::<TransactionOutput>()?;
    let data_cost_jrptr = data_cost_ptr.rptr(&env)?;
    let data_cost = data_cost_jrptr.typed_ref::<DataCost>()?;
    let result = min_ada_for_output(output, data_cost).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_minAdaRequired(env: JNIEnv, _: JObject, assets_ptr: JRPtr, has_data_hash_jboolean: jboolean, coins_per_utxo_word_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let assets_jrptr = assets_ptr.rptr(&env)?;
    let assets = assets_jrptr.typed_ref::<Value>()?;
    let has_data_hash = has_data_hash_jboolean.into_bool();
    let coins_per_utxo_word_jrptr = coins_per_utxo_word_ptr.rptr(&env)?;
    let coins_per_utxo_word = coins_per_utxo_word_jrptr.typed_ref::<BigNum>()?;
    let result = min_ada_required(assets, has_data_hash, coins_per_utxo_word).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_minFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, linear_fee_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_jrptr = tx_ptr.rptr(&env)?;
    let tx = tx_jrptr.typed_ref::<Transaction>()?;
    let linear_fee_jrptr = linear_fee_ptr.rptr(&env)?;
    let linear_fee = linear_fee_jrptr.typed_ref::<LinearFee>()?;
    let result = min_fee(tx, linear_fee).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_cslmobilebridge_Native_minScriptFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let tx_jrptr = tx_ptr.rptr(&env)?;
    let tx = tx_jrptr.typed_ref::<Transaction>()?;
    let ex_unit_prices_jrptr = ex_unit_prices_ptr.rptr(&env)?;
    let ex_unit_prices = ex_unit_prices_jrptr.typed_ref::<ExUnitPrices>()?;
    let result = min_script_fee(tx, ex_unit_prices).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


