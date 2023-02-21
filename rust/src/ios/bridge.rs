use std::slice::from_raw_parts;
use super::bridge_tools::result::*;
use super::bridge_tools::string::*;
use super::bridge_tools::data::*;
use crate::js_result::*;
use crate::panic::*;
use crate::ptr::*;
use crate::enum_maps::*;
use crate::arrays::*;
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
use cardano_serialization_lib::fees::LinearFee;
use cardano_serialization_lib::metadata::AuxiliaryData;
use cardano_serialization_lib::metadata::GeneralTransactionMetadata;
use cardano_serialization_lib::metadata::MetadataJsonSchema;
use cardano_serialization_lib::metadata::MetadataList;
use cardano_serialization_lib::metadata::MetadataMap;
use cardano_serialization_lib::metadata::TransactionMetadatum;
use cardano_serialization_lib::metadata::TransactionMetadatumKind;
use cardano_serialization_lib::metadata::TransactionMetadatumLabels;
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
use cardano_serialization_lib::protocol_types::fixed_tx::FixedTransaction;
use cardano_serialization_lib::tx_builder::CoinSelectionStrategyCIP2;
use cardano_serialization_lib::tx_builder::TransactionBuilder;
use cardano_serialization_lib::tx_builder::TransactionBuilderConfig;
use cardano_serialization_lib::tx_builder::TransactionBuilderConfigBuilder;
use cardano_serialization_lib::tx_builder::mint_builder::MintBuilder;
use cardano_serialization_lib::tx_builder::mint_builder::MintWitness;
use cardano_serialization_lib::tx_builder::tx_batch_builder::TransactionBatch;
use cardano_serialization_lib::tx_builder::tx_batch_builder::TransactionBatchList;
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

























































































































































#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_native_script(json_str: CharPtr, self_xpub_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let self_xpub: &str = self_xpub_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::utils::encode_json_str_to_native_script(json, self_xpub, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_script_fee(tx_rptr: RPtr, ex_unit_prices_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx = tx_rptr.typed_ref::<Transaction>()?;
    let ex_unit_prices = ex_unit_prices_rptr.typed_ref::<ExUnitPrices>()?;
    let result = cardano_serialization_lib::fees::min_script_fee(tx, ex_unit_prices).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_ada_required(assets_rptr: RPtr, has_data_hash: bool, coins_per_utxo_word_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let assets = assets_rptr.typed_ref::<Value>()?;
    let coins_per_utxo_word = coins_per_utxo_word_rptr.typed_ref::<BigNum>()?;
    let result = cardano_serialization_lib::utils::min_ada_required(assets, has_data_hash, coins_per_utxo_word).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_transaction(tx_body_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body = tx_body_rptr.typed_ref::<TransactionBody>()?;
    let result = cardano_serialization_lib::utils::hash_transaction(tx_body);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn make_daedalus_bootstrap_witness(tx_body_hash_rptr: RPtr, addr_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body_hash = tx_body_hash_rptr.typed_ref::<TransactionHash>()?;
    let addr = addr_rptr.typed_ref::<ByronAddress>()?;
    let key = key_rptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = cardano_serialization_lib::utils::make_daedalus_bootstrap_witness(tx_body_hash, addr, key);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_plutus_datum_to_json_str(datum_rptr: RPtr, schema_int: i32, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let datum = datum_rptr.typed_ref::<PlutusData>()?;
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::plutus::decode_plutus_datum_to_json_str(datum, schema).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_arbitrary_bytes_from_metadatum(metadata_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let metadata = metadata_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = cardano_serialization_lib::metadata::decode_arbitrary_bytes_from_metadatum(metadata).into_result()?;
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_metadatum_to_json_str(metadatum_rptr: RPtr, schema_int: i32, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let metadatum = metadatum_rptr.typed_ref::<TransactionMetadatum>()?;
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::metadata::decode_metadatum_to_json_str(metadatum, schema).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_auxiliary_data(auxiliary_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let auxiliary_data = auxiliary_data_rptr.typed_ref::<AuxiliaryData>()?;
    let result = cardano_serialization_lib::utils::hash_auxiliary_data(auxiliary_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_arbitrary_bytes_as_metadatum(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = cardano_serialization_lib::metadata::encode_arbitrary_bytes_as_metadatum(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn get_implicit_input(txbody_rptr: RPtr, pool_deposit_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let txbody = txbody_rptr.typed_ref::<TransactionBody>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = cardano_serialization_lib::utils::get_implicit_input(txbody, pool_deposit, key_deposit).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn create_send_all(address_rptr: RPtr, utxos_rptr: RPtr, config_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let address = address_rptr.typed_ref::<Address>()?;
    let utxos = utxos_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let config = config_rptr.typed_ref::<TransactionBuilderConfig>()?;
    let result = cardano_serialization_lib::tx_builder::tx_batch_builder::create_send_all(address, utxos, config).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_ada_for_output(output_rptr: RPtr, data_cost_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let output = output_rptr.typed_ref::<TransactionOutput>()?;
    let data_cost = data_cost_rptr.typed_ref::<DataCost>()?;
    let result = cardano_serialization_lib::utils::min_ada_for_output(output, data_cost).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encrypt_with_password(password_str: CharPtr, salt_str: CharPtr, nonce_str: CharPtr, data_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let password: &str = password_str.into_str();
    let salt: &str = salt_str.into_str();
    let nonce: &str = nonce_str.into_str();
    let data: &str = data_str.into_str();
    let result = cardano_serialization_lib::emip3::encrypt_with_password(password, salt, nonce, data).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn make_vkey_witness(tx_body_hash_rptr: RPtr, sk_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body_hash = tx_body_hash_rptr.typed_ref::<TransactionHash>()?;
    let sk = sk_rptr.typed_ref::<PrivateKey>()?;
    let result = cardano_serialization_lib::utils::make_vkey_witness(tx_body_hash, sk);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_metadatum(json_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json : String = json_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::metadata::encode_json_str_to_metadatum(json, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn make_icarus_bootstrap_witness(tx_body_hash_rptr: RPtr, addr_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body_hash = tx_body_hash_rptr.typed_ref::<TransactionHash>()?;
    let addr = addr_rptr.typed_ref::<ByronAddress>()?;
    let key = key_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = cardano_serialization_lib::utils::make_icarus_bootstrap_witness(tx_body_hash, addr, key);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decrypt_with_password(password_str: CharPtr, data_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let password: &str = password_str.into_str();
    let data: &str = data_str.into_str();
    let result = cardano_serialization_lib::emip3::decrypt_with_password(password, data).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_fee(tx_rptr: RPtr, linear_fee_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx = tx_rptr.typed_ref::<Transaction>()?;
    let linear_fee = linear_fee_rptr.typed_ref::<LinearFee>()?;
    let result = cardano_serialization_lib::fees::min_fee(tx, linear_fee).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn get_deposit(txbody_rptr: RPtr, pool_deposit_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let txbody = txbody_rptr.typed_ref::<TransactionBody>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = cardano_serialization_lib::utils::get_deposit(txbody, pool_deposit, key_deposit).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_script_data(redeemers_rptr: RPtr, cost_models_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let redeemers = redeemers_rptr.typed_ref::<Redeemers>()?;
    let cost_models = cost_models_rptr.typed_ref::<Costmdls>()?;
    let result = cardano_serialization_lib::utils::hash_script_data(redeemers, cost_models, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_script_data_with_datums(redeemers_rptr: RPtr, cost_models_rptr: RPtr, datums_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let redeemers = redeemers_rptr.typed_ref::<Redeemers>()?;
    let cost_models = cost_models_rptr.typed_ref::<Costmdls>()?;
    let datums = datums_rptr.typed_ref::<PlutusList>()?.clone();
    let result = cardano_serialization_lib::utils::hash_script_data(redeemers, cost_models, Some(datums));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn calculate_ex_units_ceil_cost(ex_units_rptr: RPtr, ex_unit_prices_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let ex_units = ex_units_rptr.typed_ref::<ExUnits>()?;
    let ex_unit_prices = ex_unit_prices_rptr.typed_ref::<ExUnitPrices>()?;
    let result = cardano_serialization_lib::fees::calculate_ex_units_ceil_cost(ex_units, ex_unit_prices).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_plutus_data(plutus_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let plutus_data = plutus_data_rptr.typed_ref::<PlutusData>()?;
    let result = cardano_serialization_lib::utils::hash_plutus_data(plutus_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_plutus_datum(json_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::plutus::encode_json_str_to_plutus_datum(json, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


