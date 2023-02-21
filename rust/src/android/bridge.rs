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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encodeJsonStrToNativeScript(env: JNIEnv, _: JObject, json_str: JString, self_xpub_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_minScriptFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
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


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_minAdaRequired(env: JNIEnv, _: JObject, assets_ptr: JRPtr, has_data_hash_jboolean: jboolean, coins_per_utxo_word_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashTransaction(env: JNIEnv, _: JObject, tx_body_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_makeDaedalusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decodePlutusDatumToJsonStr(env: JNIEnv, _: JObject, datum_ptr: JRPtr, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decodeArbitraryBytesFromMetadatum(env: JNIEnv, _: JObject, metadata_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decodeMetadatumToJsonStr(env: JNIEnv, _: JObject, metadatum_ptr: JRPtr, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashAuxiliaryData(env: JNIEnv, _: JObject, auxiliary_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encodeArbitraryBytesAsMetadatum(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = encode_arbitrary_bytes_as_metadatum(&bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_getImplicitInput(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_createSendAll(env: JNIEnv, _: JObject, address_ptr: JRPtr, utxos_ptr: JRPtr, config_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_minAdaForOutput(env: JNIEnv, _: JObject, output_ptr: JRPtr, data_cost_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, salt_str: JString, nonce_str: JString, data_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_makeVkeyWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, sk_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encodeJsonStrToMetadatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_makeIcarusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_decryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, data_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_minFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, linear_fee_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_getDeposit(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashScriptData(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashScriptDataWithDatums(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr, datums_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_calculateExUnitsCeilCost(env: JNIEnv, _: JObject, ex_units_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_hashPlutusData(env: JNIEnv, _: JObject, plutus_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_encodeJsonStrToPlutusDatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let schema = schema_jint.to_enum()?;
    let result = encode_json_str_to_plutus_datum(&json, schema).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


