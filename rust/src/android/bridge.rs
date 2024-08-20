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
use cardano_serialization_lib::Address;
use cardano_serialization_lib::AddressKind;
use cardano_serialization_lib::Anchor;
use cardano_serialization_lib::AnchorDataHash;
use cardano_serialization_lib::AssetName;
use cardano_serialization_lib::AssetNames;
use cardano_serialization_lib::Assets;
use cardano_serialization_lib::AuxiliaryData;
use cardano_serialization_lib::AuxiliaryDataHash;
use cardano_serialization_lib::AuxiliaryDataSet;
use cardano_serialization_lib::BaseAddress;
use cardano_serialization_lib::BigInt;
use cardano_serialization_lib::BigNum;
use cardano_serialization_lib::Bip32PrivateKey;
use cardano_serialization_lib::Bip32PublicKey;
use cardano_serialization_lib::Block;
use cardano_serialization_lib::BlockEra;
use cardano_serialization_lib::BlockHash;
use cardano_serialization_lib::BootstrapWitness;
use cardano_serialization_lib::BootstrapWitnesses;
use cardano_serialization_lib::ByronAddress;
use cardano_serialization_lib::CborContainerType;
use cardano_serialization_lib::Certificate;
use cardano_serialization_lib::CertificateKind;
use cardano_serialization_lib::Certificates;
use cardano_serialization_lib::CertificatesBuilder;
use cardano_serialization_lib::ChangeConfig;
use cardano_serialization_lib::CoinSelectionStrategyCIP2;
use cardano_serialization_lib::Committee;
use cardano_serialization_lib::CommitteeColdResign;
use cardano_serialization_lib::CommitteeHotAuth;
use cardano_serialization_lib::Constitution;
use cardano_serialization_lib::ConstrPlutusData;
use cardano_serialization_lib::CostModel;
use cardano_serialization_lib::Costmdls;
use cardano_serialization_lib::CredKind;
use cardano_serialization_lib::Credential;
use cardano_serialization_lib::Credentials;
use cardano_serialization_lib::DNSRecordAorAAAA;
use cardano_serialization_lib::DNSRecordSRV;
use cardano_serialization_lib::DRep;
use cardano_serialization_lib::DRepDeregistration;
use cardano_serialization_lib::DRepKind;
use cardano_serialization_lib::DRepRegistration;
use cardano_serialization_lib::DRepUpdate;
use cardano_serialization_lib::DRepVotingThresholds;
use cardano_serialization_lib::DataCost;
use cardano_serialization_lib::DataHash;
use cardano_serialization_lib::DatumSource;
use cardano_serialization_lib::Ed25519KeyHash;
use cardano_serialization_lib::Ed25519KeyHashes;
use cardano_serialization_lib::Ed25519Signature;
use cardano_serialization_lib::EnterpriseAddress;
use cardano_serialization_lib::ExUnitPrices;
use cardano_serialization_lib::ExUnits;
use cardano_serialization_lib::FixedBlock;
use cardano_serialization_lib::FixedTransaction;
use cardano_serialization_lib::FixedTransactionBodies;
use cardano_serialization_lib::FixedTransactionBody;
use cardano_serialization_lib::FixedVersionedBlock;
use cardano_serialization_lib::GeneralTransactionMetadata;
use cardano_serialization_lib::GenesisDelegateHash;
use cardano_serialization_lib::GenesisHash;
use cardano_serialization_lib::GenesisHashes;
use cardano_serialization_lib::GenesisKeyDelegation;
use cardano_serialization_lib::GovernanceAction;
use cardano_serialization_lib::GovernanceActionId;
use cardano_serialization_lib::GovernanceActionIds;
use cardano_serialization_lib::GovernanceActionKind;
use cardano_serialization_lib::HardForkInitiationAction;
use cardano_serialization_lib::Header;
use cardano_serialization_lib::HeaderBody;
use cardano_serialization_lib::InfoAction;
use cardano_serialization_lib::Int;
use cardano_serialization_lib::Ipv4;
use cardano_serialization_lib::Ipv6;
use cardano_serialization_lib::KESSignature;
use cardano_serialization_lib::KESVKey;
use cardano_serialization_lib::Language;
use cardano_serialization_lib::LanguageKind;
use cardano_serialization_lib::Languages;
use cardano_serialization_lib::LegacyDaedalusPrivateKey;
use cardano_serialization_lib::LinearFee;
use cardano_serialization_lib::MIRKind;
use cardano_serialization_lib::MIRPot;
use cardano_serialization_lib::MIRToStakeCredentials;
use cardano_serialization_lib::MalformedAddress;
use cardano_serialization_lib::MetadataJsonSchema;
use cardano_serialization_lib::MetadataList;
use cardano_serialization_lib::MetadataMap;
use cardano_serialization_lib::Mint;
use cardano_serialization_lib::MintAssets;
use cardano_serialization_lib::MintBuilder;
use cardano_serialization_lib::MintWitness;
use cardano_serialization_lib::MintsAssets;
use cardano_serialization_lib::MoveInstantaneousReward;
use cardano_serialization_lib::MoveInstantaneousRewardsCert;
use cardano_serialization_lib::MultiAsset;
use cardano_serialization_lib::MultiHostName;
use cardano_serialization_lib::NativeScript;
use cardano_serialization_lib::NativeScriptKind;
use cardano_serialization_lib::NativeScriptSource;
use cardano_serialization_lib::NativeScripts;
use cardano_serialization_lib::NetworkId;
use cardano_serialization_lib::NetworkIdKind;
use cardano_serialization_lib::NetworkInfo;
use cardano_serialization_lib::NewConstitutionAction;
use cardano_serialization_lib::NoConfidenceAction;
use cardano_serialization_lib::Nonce;
use cardano_serialization_lib::OperationalCert;
use cardano_serialization_lib::OutputDatum;
use cardano_serialization_lib::ParameterChangeAction;
use cardano_serialization_lib::PlutusData;
use cardano_serialization_lib::PlutusDataKind;
use cardano_serialization_lib::PlutusDatumSchema;
use cardano_serialization_lib::PlutusList;
use cardano_serialization_lib::PlutusMap;
use cardano_serialization_lib::PlutusMapValues;
use cardano_serialization_lib::PlutusScript;
use cardano_serialization_lib::PlutusScriptSource;
use cardano_serialization_lib::PlutusScripts;
use cardano_serialization_lib::PlutusWitness;
use cardano_serialization_lib::PlutusWitnesses;
use cardano_serialization_lib::Pointer;
use cardano_serialization_lib::PointerAddress;
use cardano_serialization_lib::PolicyID;
use cardano_serialization_lib::PolicyIDs;
use cardano_serialization_lib::PoolMetadata;
use cardano_serialization_lib::PoolMetadataHash;
use cardano_serialization_lib::PoolParams;
use cardano_serialization_lib::PoolRegistration;
use cardano_serialization_lib::PoolRetirement;
use cardano_serialization_lib::PoolVotingThresholds;
use cardano_serialization_lib::PrivateKey;
use cardano_serialization_lib::ProposedProtocolParameterUpdates;
use cardano_serialization_lib::ProtocolParamUpdate;
use cardano_serialization_lib::ProtocolVersion;
use cardano_serialization_lib::PublicKey;
use cardano_serialization_lib::PublicKeys;
use cardano_serialization_lib::Redeemer;
use cardano_serialization_lib::RedeemerTag;
use cardano_serialization_lib::RedeemerTagKind;
use cardano_serialization_lib::Redeemers;
use cardano_serialization_lib::Relay;
use cardano_serialization_lib::RelayKind;
use cardano_serialization_lib::Relays;
use cardano_serialization_lib::RewardAddress;
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::ScriptAll;
use cardano_serialization_lib::ScriptAny;
use cardano_serialization_lib::ScriptDataHash;
use cardano_serialization_lib::ScriptHash;
use cardano_serialization_lib::ScriptHashNamespace;
use cardano_serialization_lib::ScriptHashes;
use cardano_serialization_lib::ScriptNOfK;
use cardano_serialization_lib::ScriptPubkey;
use cardano_serialization_lib::ScriptRef;
use cardano_serialization_lib::ScriptSchema;
use cardano_serialization_lib::SingleHostAddr;
use cardano_serialization_lib::SingleHostName;
use cardano_serialization_lib::StakeAndVoteDelegation;
use cardano_serialization_lib::StakeDelegation;
use cardano_serialization_lib::StakeDeregistration;
use cardano_serialization_lib::StakeRegistration;
use cardano_serialization_lib::StakeRegistrationAndDelegation;
use cardano_serialization_lib::StakeVoteRegistrationAndDelegation;
use cardano_serialization_lib::Strings;
use cardano_serialization_lib::TimelockExpiry;
use cardano_serialization_lib::TimelockStart;
use cardano_serialization_lib::Transaction;
use cardano_serialization_lib::TransactionBatch;
use cardano_serialization_lib::TransactionBatchList;
use cardano_serialization_lib::TransactionBodies;
use cardano_serialization_lib::TransactionBody;
use cardano_serialization_lib::TransactionBuilder;
use cardano_serialization_lib::TransactionBuilderConfig;
use cardano_serialization_lib::TransactionBuilderConfigBuilder;
use cardano_serialization_lib::TransactionHash;
use cardano_serialization_lib::TransactionInput;
use cardano_serialization_lib::TransactionInputs;
use cardano_serialization_lib::TransactionMetadatum;
use cardano_serialization_lib::TransactionMetadatumKind;
use cardano_serialization_lib::TransactionMetadatumLabels;
use cardano_serialization_lib::TransactionOutput;
use cardano_serialization_lib::TransactionOutputAmountBuilder;
use cardano_serialization_lib::TransactionOutputBuilder;
use cardano_serialization_lib::TransactionOutputs;
use cardano_serialization_lib::TransactionUnspentOutput;
use cardano_serialization_lib::TransactionUnspentOutputs;
use cardano_serialization_lib::TransactionWitnessSet;
use cardano_serialization_lib::TransactionWitnessSets;
use cardano_serialization_lib::TreasuryWithdrawals;
use cardano_serialization_lib::TreasuryWithdrawalsAction;
use cardano_serialization_lib::TxBuilderConstants;
use cardano_serialization_lib::TxInputsBuilder;
use cardano_serialization_lib::URL;
use cardano_serialization_lib::UnitInterval;
use cardano_serialization_lib::Update;
use cardano_serialization_lib::UpdateCommitteeAction;
use cardano_serialization_lib::VRFCert;
use cardano_serialization_lib::VRFKeyHash;
use cardano_serialization_lib::VRFVKey;
use cardano_serialization_lib::Value;
use cardano_serialization_lib::VersionedBlock;
use cardano_serialization_lib::Vkey;
use cardano_serialization_lib::Vkeys;
use cardano_serialization_lib::Vkeywitness;
use cardano_serialization_lib::Vkeywitnesses;
use cardano_serialization_lib::VoteDelegation;
use cardano_serialization_lib::VoteKind;
use cardano_serialization_lib::VoteRegistrationAndDelegation;
use cardano_serialization_lib::Voter;
use cardano_serialization_lib::VoterKind;
use cardano_serialization_lib::Voters;
use cardano_serialization_lib::VotingBuilder;
use cardano_serialization_lib::VotingProcedure;
use cardano_serialization_lib::VotingProcedures;
use cardano_serialization_lib::VotingProposal;
use cardano_serialization_lib::VotingProposalBuilder;
use cardano_serialization_lib::VotingProposals;
use cardano_serialization_lib::Withdrawals;
use cardano_serialization_lib::WithdrawalsBuilder;
use cardano_serialization_lib::calculate_ex_units_ceil_cost;
use cardano_serialization_lib::create_send_all;
use cardano_serialization_lib::decode_arbitrary_bytes_from_metadatum;
use cardano_serialization_lib::decode_metadatum_to_json_str;
use cardano_serialization_lib::decode_plutus_datum_to_json_str;
use cardano_serialization_lib::decrypt_with_password;
use cardano_serialization_lib::encode_arbitrary_bytes_as_metadatum;
use cardano_serialization_lib::encode_json_str_to_metadatum;
use cardano_serialization_lib::encode_json_str_to_native_script;
use cardano_serialization_lib::encode_json_str_to_plutus_datum;
use cardano_serialization_lib::encrypt_with_password;
use cardano_serialization_lib::get_deposit;
use cardano_serialization_lib::get_implicit_input;
use cardano_serialization_lib::hash_auxiliary_data;
use cardano_serialization_lib::hash_plutus_data;
use cardano_serialization_lib::hash_script_data;
use cardano_serialization_lib::hash_transaction;
use cardano_serialization_lib::make_daedalus_bootstrap_witness;
use cardano_serialization_lib::make_icarus_bootstrap_witness;
use cardano_serialization_lib::make_vkey_witness;
use cardano_serialization_lib::min_ada_for_output;
use cardano_serialization_lib::min_fee;
use cardano_serialization_lib::min_ref_script_fee;
use cardano_serialization_lib::min_script_fee;


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressFromBytes(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Address::from_bytes(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Address::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.payment_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressIsMalformed(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.is_malformed();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Address::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressToBech32WithPrefix(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = Address::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1addressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Anchor>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Anchor::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Anchor>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Anchor::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Anchor>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Anchor::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorUrl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Anchor>()?;
    let result = self_rptr.url();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorAnchorDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Anchor>()?;
    let result = self_rptr.anchor_data_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorNew(env: JNIEnv, _: JObject, anchor_url_ptr: JRPtr, anchor_data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let anchor_url_jrptr = anchor_url_ptr.rptr(&env)?;
    let anchor_url = anchor_url_jrptr.typed_ref::<URL>()?;
    let anchor_data_hash_jrptr = anchor_data_hash_ptr.rptr(&env)?;
    let anchor_data_hash = anchor_data_hash_jrptr.typed_ref::<AnchorDataHash>()?;
    let result = Anchor::new(anchor_url, anchor_data_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AnchorDataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AnchorDataHash>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AnchorDataHash>()?;
    let prefix = prefix_str.string(&env)?;
    let result = self_rptr.to_bech32(&prefix).into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = AnchorDataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AnchorDataHash>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1anchorDataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = AnchorDataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AssetName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AssetName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AssetName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameNew(env: JNIEnv, _: JObject, name_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let name = env.convert_byte_array(name_jarray).into_result()?;
    let result = AssetName::new(name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNameName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AssetNames::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AssetNames::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AssetNames::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AssetNames::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetNamesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Assets::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Assets::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Assets::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Assets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1assetsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AuxiliaryData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = AuxiliaryData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = AuxiliaryData::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AuxiliaryData::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr, metadata_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, native_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataPreferAlonzoFormat(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<AuxiliaryData>()?;
    let result = self_rptr.prefer_alonzo_format();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetPreferAlonzoFormat(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefer_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = AuxiliaryDataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = AuxiliaryDataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = AuxiliaryDataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = AuxiliaryDataSet::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, tx_index_jlong: jlong, data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, tx_index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1auxiliaryDataSetIndices(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr, stake_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<Credential>()?;
    let stake_jrptr = stake_ptr.rptr(&env)?;
    let stake = stake_jrptr.typed_ref::<Credential>()?;
    let result = BaseAddress::new(network, payment, stake);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressStakeCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1baseAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BaseAddress>()?;
    let result = self_rptr.network_id();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BigInt::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BigInt::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BigInt::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.is_zero();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntAsU64(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntAsInt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntFromStr(env: JNIEnv, _: JObject, text_str: JString) -> jobject {
  handle_exception_result(|| { 
    let text = text_str.string(&env)?;
    let result = BigInt::from_str(&text).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.sub(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntMul(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntPow(env: JNIEnv, _: JObject, self_ptr: JRPtr, exp_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let exp = u32::try_from_jlong(exp_jlong)?;
    let result = self_rptr.pow(exp);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntOne(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigInt::one();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntZero(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigInt::zero();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntAbs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.abs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntIncrement(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntDivCeil(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigIntDivFloor(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigInt>()?;
    let other_jrptr = other_ptr.rptr(&env)?;
    let other = other_jrptr.typed_ref::<BigInt>()?;
    let result = self_rptr.div_floor(other);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BigNum::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BigNum::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BigNum::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumFromStr(env: JNIEnv, _: JObject, string_str: JString) -> jobject {
  handle_exception_result(|| { 
    let string = string_str.string(&env)?;
    let result = BigNum::from_str(&string).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumZero(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::zero();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumOne(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::one();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.is_zero();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumDivFloor(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumCheckedMul(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumCheckedAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumCheckedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumClampedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, other_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumCompare(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumLessThan(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BigNum>()?;
    let rhs_value_jrptr = rhs_value_ptr.rptr(&env)?;
    let rhs_value = rhs_value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.less_than(rhs_value);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumMaxValue(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BigNum::max_value();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bigNumMax(env: JNIEnv, _: JObject, a_ptr: JRPtr, b_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyDerive(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyFrom_1128Xprv(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PrivateKey::from_128_xprv(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyTo_1128Xprv(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyGenerateEd25519Bip32(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Bip32PrivateKey::generate_ed25519_bip32().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyToRawKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyToPublic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PrivateKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Bip32PrivateKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyFromBip39Entropy(env: JNIEnv, _: JObject, entropy_jarray: jbyteArray, password_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PrivateKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Bip32PrivateKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyDerive(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyToRawKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Bip32PublicKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Bip32PublicKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bip32PublicKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Bip32PublicKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Block::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Block::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Block::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHeader(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockTransactionBodies(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockTransactionWitnessSets(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockAuxiliaryDataSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockInvalidTransactions(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockNew(env: JNIEnv, _: JObject, header_ptr: JRPtr, transaction_bodies_ptr: JRPtr, transaction_witness_sets_ptr: JRPtr, auxiliary_data_set_ptr: JRPtr, invalid_transactions_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BlockHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = BlockHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1blockHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = BlockHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BootstrapWitness::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BootstrapWitness::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BootstrapWitness::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessSignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessChainCode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessAttributes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessNew(env: JNIEnv, _: JObject, vkey_ptr: JRPtr, signature_ptr: JRPtr, chain_code_jarray: jbyteArray, attributes_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = BootstrapWitnesses::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = BootstrapWitnesses::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = BootstrapWitnesses::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = BootstrapWitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1bootstrapWitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<BootstrapWitnesses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<BootstrapWitness>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressToBase58(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ByronAddress::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressByronProtocolMagic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressAttributes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressFromBase58(env: JNIEnv, _: JObject, s_str: JString) -> jobject {
  handle_exception_result(|| { 
    let s = s_str.string(&env)?;
    let result = ByronAddress::from_base58(&s).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressIcarusFromKey(env: JNIEnv, _: JObject, key_ptr: JRPtr, protocol_magic_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressIsValid(env: JNIEnv, _: JObject, s_str: JString) -> jobject {
  handle_exception_result(|| { 
    let s = s_str.string(&env)?;
    let result = ByronAddress::is_valid(&s);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1byronAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Certificate::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Certificate::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Certificate::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeRegistration(env: JNIEnv, _: JObject, stake_registration_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewRegCert(env: JNIEnv, _: JObject, stake_registration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_registration_jrptr = stake_registration_ptr.rptr(&env)?;
    let stake_registration = stake_registration_jrptr.typed_ref::<StakeRegistration>()?;
    let result = Certificate::new_reg_cert(stake_registration).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeDeregistration(env: JNIEnv, _: JObject, stake_deregistration_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewUnregCert(env: JNIEnv, _: JObject, stake_deregistration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_deregistration_jrptr = stake_deregistration_ptr.rptr(&env)?;
    let stake_deregistration = stake_deregistration_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = Certificate::new_unreg_cert(stake_deregistration).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeDelegation(env: JNIEnv, _: JObject, stake_delegation_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewPoolRegistration(env: JNIEnv, _: JObject, pool_registration_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewPoolRetirement(env: JNIEnv, _: JObject, pool_retirement_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewGenesisKeyDelegation(env: JNIEnv, _: JObject, genesis_key_delegation_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewMoveInstantaneousRewardsCert(env: JNIEnv, _: JObject, move_instantaneous_rewards_cert_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewCommitteeHotAuth(env: JNIEnv, _: JObject, committee_hot_auth_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_hot_auth_jrptr = committee_hot_auth_ptr.rptr(&env)?;
    let committee_hot_auth = committee_hot_auth_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = Certificate::new_committee_hot_auth(committee_hot_auth);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewCommitteeColdResign(env: JNIEnv, _: JObject, committee_cold_resign_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_cold_resign_jrptr = committee_cold_resign_ptr.rptr(&env)?;
    let committee_cold_resign = committee_cold_resign_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = Certificate::new_committee_cold_resign(committee_cold_resign);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewDrepDeregistration(env: JNIEnv, _: JObject, drep_deregistration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let drep_deregistration_jrptr = drep_deregistration_ptr.rptr(&env)?;
    let drep_deregistration = drep_deregistration_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = Certificate::new_drep_deregistration(drep_deregistration);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewDrepRegistration(env: JNIEnv, _: JObject, drep_registration_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let drep_registration_jrptr = drep_registration_ptr.rptr(&env)?;
    let drep_registration = drep_registration_jrptr.typed_ref::<DRepRegistration>()?;
    let result = Certificate::new_drep_registration(drep_registration);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewDrepUpdate(env: JNIEnv, _: JObject, drep_update_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let drep_update_jrptr = drep_update_ptr.rptr(&env)?;
    let drep_update = drep_update_jrptr.typed_ref::<DRepUpdate>()?;
    let result = Certificate::new_drep_update(drep_update);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeAndVoteDelegation(env: JNIEnv, _: JObject, stake_and_vote_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_and_vote_delegation_jrptr = stake_and_vote_delegation_ptr.rptr(&env)?;
    let stake_and_vote_delegation = stake_and_vote_delegation_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = Certificate::new_stake_and_vote_delegation(stake_and_vote_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeRegistrationAndDelegation(env: JNIEnv, _: JObject, stake_registration_and_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_registration_and_delegation_jrptr = stake_registration_and_delegation_ptr.rptr(&env)?;
    let stake_registration_and_delegation = stake_registration_and_delegation_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = Certificate::new_stake_registration_and_delegation(stake_registration_and_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewStakeVoteRegistrationAndDelegation(env: JNIEnv, _: JObject, stake_vote_registration_and_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_vote_registration_and_delegation_jrptr = stake_vote_registration_and_delegation_ptr.rptr(&env)?;
    let stake_vote_registration_and_delegation = stake_vote_registration_and_delegation_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = Certificate::new_stake_vote_registration_and_delegation(stake_vote_registration_and_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewVoteDelegation(env: JNIEnv, _: JObject, vote_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let vote_delegation_jrptr = vote_delegation_ptr.rptr(&env)?;
    let vote_delegation = vote_delegation_jrptr.typed_ref::<VoteDelegation>()?;
    let result = Certificate::new_vote_delegation(vote_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateNewVoteRegistrationAndDelegation(env: JNIEnv, _: JObject, vote_registration_and_delegation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let vote_registration_and_delegation_jrptr = vote_registration_and_delegation_ptr.rptr(&env)?;
    let vote_registration_and_delegation = vote_registration_and_delegation_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = Certificate::new_vote_registration_and_delegation(vote_registration_and_delegation);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeRegistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsRegCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_reg_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeDeregistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsUnregCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_unreg_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsPoolRegistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsPoolRetirement(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsGenesisKeyDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsMoveInstantaneousRewardsCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsCommitteeHotAuth(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_committee_hot_auth();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsCommitteeColdResign(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_committee_cold_resign();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsDrepDeregistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_drep_deregistration();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsDrepRegistration(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_drep_registration();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsDrepUpdate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_drep_update();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeAndVoteDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_and_vote_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeRegistrationAndDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_registration_and_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsStakeVoteRegistrationAndDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_stake_vote_registration_and_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsVoteDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_vote_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateAsVoteRegistrationAndDelegation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.as_vote_registration_and_delegation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificateHasRequiredScriptWitness(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.has_required_script_witness();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Certificates::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Certificates::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Certificates::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Certificates::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Certificates>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Certificate>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = CertificatesBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, cert_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let cert_jrptr = cert_ptr.rptr(&env)?;
    let cert = cert_jrptr.typed_ref::<Certificate>()?;
    self_rptr.add(cert).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderAddWithPlutusWitness(env: JNIEnv, _: JObject, self_ptr: JRPtr, cert_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let cert_jrptr = cert_ptr.rptr(&env)?;
    let cert = cert_jrptr.typed_ref::<Certificate>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    self_rptr.add_with_plutus_witness(cert, witness).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderAddWithNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr, cert_ptr: JRPtr, native_script_source_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let cert_jrptr = cert_ptr.rptr(&env)?;
    let cert = cert_jrptr.typed_ref::<Certificate>()?;
    let native_script_source_jrptr = native_script_source_ptr.rptr(&env)?;
    let native_script_source = native_script_source_jrptr.typed_ref::<NativeScriptSource>()?;
    self_rptr.add_with_native_script(cert, native_script_source).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_rptr.get_plutus_witnesses();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderGetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_rptr.get_native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderGetCertificatesRefund(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.get_certificates_refund(pool_deposit, key_deposit).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderGetCertificatesDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let pool_deposit_jrptr = pool_deposit_ptr.rptr(&env)?;
    let pool_deposit = pool_deposit_jrptr.typed_ref::<BigNum>()?;
    let key_deposit_jrptr = key_deposit_ptr.rptr(&env)?;
    let key_deposit = key_deposit_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.get_certificates_deposit(pool_deposit, key_deposit).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1certificatesBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_rptr.build();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1changeConfigNew(env: JNIEnv, _: JObject, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = ChangeConfig::new(address);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1changeConfigChangeAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ChangeConfig>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.change_address(address);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1changeConfigChangePlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ChangeConfig>()?;
    let plutus_data_jrptr = plutus_data_ptr.rptr(&env)?;
    let plutus_data = plutus_data_jrptr.typed_ref::<OutputDatum>()?;
    let result = self_rptr.change_plutus_data(plutus_data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1changeConfigChangeScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ref_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ChangeConfig>()?;
    let script_ref_jrptr = script_ref_ptr.rptr(&env)?;
    let script_ref = script_ref_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.change_script_ref(script_ref);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Committee::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Committee::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Committee::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeNew(env: JNIEnv, _: JObject, quorum_threshold_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let quorum_threshold_jrptr = quorum_threshold_ptr.rptr(&env)?;
    let quorum_threshold = quorum_threshold_jrptr.typed_ref::<UnitInterval>()?;
    let result = Committee::new(quorum_threshold);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeMembersKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let result = self_rptr.members_keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeQuorumThreshold(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let result = self_rptr.quorum_threshold();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeAddMember(env: JNIEnv, _: JObject, self_ptr: JRPtr, committee_cold_credential_ptr: JRPtr, epoch_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let committee_cold_credential_jrptr = committee_cold_credential_ptr.rptr(&env)?;
    let committee_cold_credential = committee_cold_credential_jrptr.typed_ref::<Credential>()?;
    let epoch = u32::try_from_jlong(epoch_jlong)?;
    self_rptr.add_member(committee_cold_credential, epoch);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeGetMemberEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr, committee_cold_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Committee>()?;
    let committee_cold_credential_jrptr = committee_cold_credential_ptr.rptr(&env)?;
    let committee_cold_credential = committee_cold_credential_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.get_member_epoch(committee_cold_credential);
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = CommitteeColdResign::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = CommitteeColdResign::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = CommitteeColdResign::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignCommitteeColdKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.committee_cold_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignNew(env: JNIEnv, _: JObject, committee_cold_key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_cold_key_jrptr = committee_cold_key_ptr.rptr(&env)?;
    let committee_cold_key = committee_cold_key_jrptr.typed_ref::<Credential>()?;
    let result = CommitteeColdResign::new(committee_cold_key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignNewWithAnchor(env: JNIEnv, _: JObject, committee_cold_key_ptr: JRPtr, anchor_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_cold_key_jrptr = committee_cold_key_ptr.rptr(&env)?;
    let committee_cold_key = committee_cold_key_jrptr.typed_ref::<Credential>()?;
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let result = CommitteeColdResign::new_with_anchor(committee_cold_key, anchor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeColdResignHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = CommitteeHotAuth::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = CommitteeHotAuth::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = CommitteeHotAuth::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthCommitteeColdKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.committee_cold_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthCommitteeHotKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.committee_hot_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthNew(env: JNIEnv, _: JObject, committee_cold_key_ptr: JRPtr, committee_hot_key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_cold_key_jrptr = committee_cold_key_ptr.rptr(&env)?;
    let committee_cold_key = committee_cold_key_jrptr.typed_ref::<Credential>()?;
    let committee_hot_key_jrptr = committee_hot_key_ptr.rptr(&env)?;
    let committee_hot_key = committee_hot_key_jrptr.typed_ref::<Credential>()?;
    let result = CommitteeHotAuth::new(committee_cold_key, committee_hot_key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1committeeHotAuthHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Constitution>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Constitution::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Constitution>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Constitution::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Constitution>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Constitution::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Constitution>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Constitution>()?;
    let result = self_rptr.script_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionNew(env: JNIEnv, _: JObject, anchor_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let result = Constitution::new(anchor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constitutionNewWithScriptHash(env: JNIEnv, _: JObject, anchor_ptr: JRPtr, script_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = Constitution::new_with_script_hash(anchor, script_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ConstrPlutusData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ConstrPlutusData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataAlternative(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1constrPlutusDataNew(env: JNIEnv, _: JObject, alternative_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = CostModel::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = CostModel::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = CostModel::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = CostModel::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelSet(env: JNIEnv, _: JObject, self_ptr: JRPtr, operation_jlong: jlong, cost_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, operation_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costModelLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Costmdls::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Costmdls::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Costmdls::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Costmdls::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1costmdlsRetainLanguageVersions(env: JNIEnv, _: JObject, self_ptr: JRPtr, languages_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialFromKeyhash(env: JNIEnv, _: JObject, hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = Credential::from_keyhash(hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialFromScripthash(env: JNIEnv, _: JObject, hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hash_jrptr = hash_ptr.rptr(&env)?;
    let hash = hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = Credential::from_scripthash(hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialToKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.to_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialToScripthash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.to_scripthash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialHasScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.has_script_hash();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Credential::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Credential::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Credential::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Credentials::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Credentials::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Credentials::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Credentials::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1credentialsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Credentials>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DNSRecordAorAAAA::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DNSRecordAorAAAA::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAAFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DNSRecordAorAAAA::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAANew(env: JNIEnv, _: JObject, dns_name_str: JString) -> jobject {
  handle_exception_result(|| { 
    let dns_name = dns_name_str.string(&env)?;
    let result = DNSRecordAorAAAA::new(dns_name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordAorAAAARecord(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DNSRecordSRV::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DNSRecordSRV::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DNSRecordSRV::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVNew(env: JNIEnv, _: JObject, dns_name_str: JString) -> jobject {
  handle_exception_result(|| { 
    let dns_name = dns_name_str.string(&env)?;
    let result = DNSRecordSRV::new(dns_name).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dNSRecordSRVRecord(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DRep::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DRep::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DRep::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepNewKeyHash(env: JNIEnv, _: JObject, key_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let key_hash_jrptr = key_hash_ptr.rptr(&env)?;
    let key_hash = key_hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = DRep::new_key_hash(key_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepNewScriptHash(env: JNIEnv, _: JObject, script_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = DRep::new_script_hash(script_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepNewAlwaysAbstain(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = DRep::new_always_abstain();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepNewAlwaysNoConfidence(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = DRep::new_always_no_confidence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepNewFromCredential(env: JNIEnv, _: JObject, cred_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<Credential>()?;
    let result = DRep::new_from_credential(cred);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToKeyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_key_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_script_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRep>()?;
    let result = self_rptr.to_bech32().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = DRep::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DRepDeregistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DRepDeregistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DRepDeregistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationVotingCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.voting_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationNew(env: JNIEnv, _: JObject, voting_credential_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let voting_credential_jrptr = voting_credential_ptr.rptr(&env)?;
    let voting_credential = voting_credential_jrptr.typed_ref::<Credential>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = DRepDeregistration::new(voting_credential, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepDeregistrationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepDeregistration>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DRepRegistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DRepRegistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DRepRegistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationVotingCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.voting_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationNew(env: JNIEnv, _: JObject, voting_credential_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let voting_credential_jrptr = voting_credential_ptr.rptr(&env)?;
    let voting_credential = voting_credential_jrptr.typed_ref::<Credential>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = DRepRegistration::new(voting_credential, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationNewWithAnchor(env: JNIEnv, _: JObject, voting_credential_ptr: JRPtr, coin_ptr: JRPtr, anchor_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let voting_credential_jrptr = voting_credential_ptr.rptr(&env)?;
    let voting_credential = voting_credential_jrptr.typed_ref::<Credential>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let result = DRepRegistration::new_with_anchor(voting_credential, coin, anchor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepRegistrationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepRegistration>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DRepUpdate::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DRepUpdate::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DRepUpdate::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateVotingCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.voting_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateNew(env: JNIEnv, _: JObject, voting_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let voting_credential_jrptr = voting_credential_ptr.rptr(&env)?;
    let voting_credential = voting_credential_jrptr.typed_ref::<Credential>()?;
    let result = DRepUpdate::new(voting_credential);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateNewWithAnchor(env: JNIEnv, _: JObject, voting_credential_ptr: JRPtr, anchor_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let voting_credential_jrptr = voting_credential_ptr.rptr(&env)?;
    let voting_credential = voting_credential_jrptr.typed_ref::<Credential>()?;
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let result = DRepUpdate::new_with_anchor(voting_credential, anchor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepUpdateHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepUpdate>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DRepVotingThresholds::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = DRepVotingThresholds::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = DRepVotingThresholds::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsNew(env: JNIEnv, _: JObject, motion_no_confidence_ptr: JRPtr, committee_normal_ptr: JRPtr, committee_no_confidence_ptr: JRPtr, update_constitution_ptr: JRPtr, hard_fork_initiation_ptr: JRPtr, pp_network_group_ptr: JRPtr, pp_economic_group_ptr: JRPtr, pp_technical_group_ptr: JRPtr, pp_governance_group_ptr: JRPtr, treasury_withdrawal_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let motion_no_confidence_jrptr = motion_no_confidence_ptr.rptr(&env)?;
    let motion_no_confidence = motion_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    let committee_normal_jrptr = committee_normal_ptr.rptr(&env)?;
    let committee_normal = committee_normal_jrptr.typed_ref::<UnitInterval>()?;
    let committee_no_confidence_jrptr = committee_no_confidence_ptr.rptr(&env)?;
    let committee_no_confidence = committee_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    let update_constitution_jrptr = update_constitution_ptr.rptr(&env)?;
    let update_constitution = update_constitution_jrptr.typed_ref::<UnitInterval>()?;
    let hard_fork_initiation_jrptr = hard_fork_initiation_ptr.rptr(&env)?;
    let hard_fork_initiation = hard_fork_initiation_jrptr.typed_ref::<UnitInterval>()?;
    let pp_network_group_jrptr = pp_network_group_ptr.rptr(&env)?;
    let pp_network_group = pp_network_group_jrptr.typed_ref::<UnitInterval>()?;
    let pp_economic_group_jrptr = pp_economic_group_ptr.rptr(&env)?;
    let pp_economic_group = pp_economic_group_jrptr.typed_ref::<UnitInterval>()?;
    let pp_technical_group_jrptr = pp_technical_group_ptr.rptr(&env)?;
    let pp_technical_group = pp_technical_group_jrptr.typed_ref::<UnitInterval>()?;
    let pp_governance_group_jrptr = pp_governance_group_ptr.rptr(&env)?;
    let pp_governance_group = pp_governance_group_jrptr.typed_ref::<UnitInterval>()?;
    let treasury_withdrawal_jrptr = treasury_withdrawal_ptr.rptr(&env)?;
    let treasury_withdrawal = treasury_withdrawal_jrptr.typed_ref::<UnitInterval>()?;
    let result = DRepVotingThresholds::new(motion_no_confidence, committee_normal, committee_no_confidence, update_constitution, hard_fork_initiation, pp_network_group, pp_economic_group, pp_technical_group, pp_governance_group, treasury_withdrawal);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetMotionNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr, motion_no_confidence_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let motion_no_confidence_jrptr = motion_no_confidence_ptr.rptr(&env)?;
    let motion_no_confidence = motion_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_motion_no_confidence(motion_no_confidence);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetCommitteeNormal(env: JNIEnv, _: JObject, self_ptr: JRPtr, committee_normal_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let committee_normal_jrptr = committee_normal_ptr.rptr(&env)?;
    let committee_normal = committee_normal_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_committee_normal(committee_normal);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetCommitteeNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr, committee_no_confidence_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let committee_no_confidence_jrptr = committee_no_confidence_ptr.rptr(&env)?;
    let committee_no_confidence = committee_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_committee_no_confidence(committee_no_confidence);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetUpdateConstitution(env: JNIEnv, _: JObject, self_ptr: JRPtr, update_constitution_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let update_constitution_jrptr = update_constitution_ptr.rptr(&env)?;
    let update_constitution = update_constitution_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_update_constitution(update_constitution);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetHardForkInitiation(env: JNIEnv, _: JObject, self_ptr: JRPtr, hard_fork_initiation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let hard_fork_initiation_jrptr = hard_fork_initiation_ptr.rptr(&env)?;
    let hard_fork_initiation = hard_fork_initiation_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_hard_fork_initiation(hard_fork_initiation);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetPpNetworkGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr, pp_network_group_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let pp_network_group_jrptr = pp_network_group_ptr.rptr(&env)?;
    let pp_network_group = pp_network_group_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_pp_network_group(pp_network_group);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetPpEconomicGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr, pp_economic_group_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let pp_economic_group_jrptr = pp_economic_group_ptr.rptr(&env)?;
    let pp_economic_group = pp_economic_group_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_pp_economic_group(pp_economic_group);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetPpTechnicalGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr, pp_technical_group_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let pp_technical_group_jrptr = pp_technical_group_ptr.rptr(&env)?;
    let pp_technical_group = pp_technical_group_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_pp_technical_group(pp_technical_group);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetPpGovernanceGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr, pp_governance_group_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let pp_governance_group_jrptr = pp_governance_group_ptr.rptr(&env)?;
    let pp_governance_group = pp_governance_group_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_pp_governance_group(pp_governance_group);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsSetTreasuryWithdrawal(env: JNIEnv, _: JObject, self_ptr: JRPtr, treasury_withdrawal_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let treasury_withdrawal_jrptr = treasury_withdrawal_ptr.rptr(&env)?;
    let treasury_withdrawal = treasury_withdrawal_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_treasury_withdrawal(treasury_withdrawal);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsMotionNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.motion_no_confidence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsCommitteeNormal(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.committee_normal();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsCommitteeNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.committee_no_confidence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsUpdateConstitution(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.update_constitution();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsHardForkInitiation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.hard_fork_initiation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsPpNetworkGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.pp_network_group();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsPpEconomicGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.pp_economic_group();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsPpTechnicalGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.pp_technical_group();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsPpGovernanceGroup(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.pp_governance_group();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dRepVotingThresholdsTreasuryWithdrawal(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<DRepVotingThresholds>()?;
    let result = self_rptr.treasury_withdrawal();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataCostNewCoinsPerByte(env: JNIEnv, _: JObject, coins_per_byte_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataCostCoinsPerByte(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = DataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = DataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1dataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = DataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1datumSourceNew(env: JNIEnv, _: JObject, datum_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1datumSourceNewRefInput(env: JNIEnv, _: JObject, input_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519KeyHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = Ed25519KeyHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = Ed25519KeyHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519KeyHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ed25519KeyHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ed25519KeyHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Ed25519KeyHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesContains(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_rptr.contains(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519KeyHashesToOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = Ed25519Signature::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureFromHex(env: JNIEnv, _: JObject, input_str: JString) -> jobject {
  handle_exception_result(|| { 
    let input = input_str.string(&env)?;
    let result = Ed25519Signature::from_hex(&input).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ed25519SignatureFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ed25519Signature::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1enterpriseAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<Credential>()?;
    let result = EnterpriseAddress::new(network, payment);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1enterpriseAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1enterpriseAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1enterpriseAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1enterpriseAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<EnterpriseAddress>()?;
    let result = self_rptr.network_id();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ExUnitPrices::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ExUnitPrices::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ExUnitPrices::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesMemPrice(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesStepPrice(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitPricesNew(env: JNIEnv, _: JObject, mem_price_ptr: JRPtr, step_price_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ExUnits::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ExUnits::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ExUnits::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsMem(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsSteps(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1exUnitsNew(env: JNIEnv, _: JObject, mem_ptr: JRPtr, steps_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedBlock::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedBlock::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockHeader(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.header();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockTransactionBodies(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.transaction_bodies();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockTransactionWitnessSets(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.transaction_witness_sets();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockAuxiliaryDataSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.auxiliary_data_set();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockInvalidTransactions(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.invalid_transactions();
    u32_array_to_base64(&result).jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedBlockBlockHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedBlock>()?;
    let result = self_rptr.block_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedTransaction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedTransaction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionNew(env: JNIEnv, _: JObject, raw_body_jarray: jbyteArray, raw_witness_set_jarray: jbyteArray, is_valid_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionNewWithAuxiliary(env: JNIEnv, _: JObject, raw_body_jarray: jbyteArray, raw_witness_set_jarray: jbyteArray, raw_auxiliary_data_jarray: jbyteArray, is_valid_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionRawBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionSetBody(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_body_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionSetWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_witness_set_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionRawWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionSetIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr, valid_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransaction>()?;
    let result = self_rptr.is_valid();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionSetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr, raw_auxiliary_data_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionRawAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedTransactionBodies::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedTransactionBodies::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = FixedTransactionBodies::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBodies>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBodies>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodiesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBodies>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<FixedTransactionBody>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedTransactionBody::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedTransactionBody::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodyTransactionBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBody>()?;
    let result = self_rptr.transaction_body();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodyTxHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBody>()?;
    let result = self_rptr.tx_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedTransactionBodyOriginalBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedTransactionBody>()?;
    let result = self_rptr.original_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedVersionedBlockFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = FixedVersionedBlock::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedVersionedBlockFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = FixedVersionedBlock::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedVersionedBlockBlock(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedVersionedBlock>()?;
    let result = self_rptr.block();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1fixedVersionedBlockEra(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<FixedVersionedBlock>()?;
    let result = self_rptr.era();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GeneralTransactionMetadata::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GeneralTransactionMetadata::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GeneralTransactionMetadata::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = GeneralTransactionMetadata::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1generalTransactionMetadataKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisDelegateHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = GenesisDelegateHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisDelegateHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = GenesisDelegateHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = GenesisHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = GenesisHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GenesisHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GenesisHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = GenesisHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GenesisKeyDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GenesisKeyDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GenesisKeyDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationGenesishash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationGenesisDelegateHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationVrfKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1genesisKeyDelegationNew(env: JNIEnv, _: JObject, genesishash_ptr: JRPtr, genesis_delegate_hash_ptr: JRPtr, vrf_keyhash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GovernanceAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GovernanceAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GovernanceAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewParameterChangeAction(env: JNIEnv, _: JObject, parameter_change_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let parameter_change_action_jrptr = parameter_change_action_ptr.rptr(&env)?;
    let parameter_change_action = parameter_change_action_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = GovernanceAction::new_parameter_change_action(parameter_change_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewHardForkInitiationAction(env: JNIEnv, _: JObject, hard_fork_initiation_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let hard_fork_initiation_action_jrptr = hard_fork_initiation_action_ptr.rptr(&env)?;
    let hard_fork_initiation_action = hard_fork_initiation_action_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = GovernanceAction::new_hard_fork_initiation_action(hard_fork_initiation_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewTreasuryWithdrawalsAction(env: JNIEnv, _: JObject, treasury_withdrawals_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let treasury_withdrawals_action_jrptr = treasury_withdrawals_action_ptr.rptr(&env)?;
    let treasury_withdrawals_action = treasury_withdrawals_action_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = GovernanceAction::new_treasury_withdrawals_action(treasury_withdrawals_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewNoConfidenceAction(env: JNIEnv, _: JObject, no_confidence_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let no_confidence_action_jrptr = no_confidence_action_ptr.rptr(&env)?;
    let no_confidence_action = no_confidence_action_jrptr.typed_ref::<NoConfidenceAction>()?;
    let result = GovernanceAction::new_no_confidence_action(no_confidence_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewNewCommitteeAction(env: JNIEnv, _: JObject, new_committee_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let new_committee_action_jrptr = new_committee_action_ptr.rptr(&env)?;
    let new_committee_action = new_committee_action_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = GovernanceAction::new_new_committee_action(new_committee_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewNewConstitutionAction(env: JNIEnv, _: JObject, new_constitution_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let new_constitution_action_jrptr = new_constitution_action_ptr.rptr(&env)?;
    let new_constitution_action = new_constitution_action_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = GovernanceAction::new_new_constitution_action(new_constitution_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionNewInfoAction(env: JNIEnv, _: JObject, info_action_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let info_action_jrptr = info_action_ptr.rptr(&env)?;
    let info_action = info_action_jrptr.typed_ref::<InfoAction>()?;
    let result = GovernanceAction::new_info_action(info_action);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsParameterChangeAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_parameter_change_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsHardForkInitiationAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_hard_fork_initiation_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsTreasuryWithdrawalsAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_treasury_withdrawals_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsNoConfidenceAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_no_confidence_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsNewCommitteeAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_new_committee_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsNewConstitutionAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_new_constitution_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionAsInfoAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceAction>()?;
    let result = self_rptr.as_info_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = GovernanceActionId::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = GovernanceActionId::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GovernanceActionId::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdTransactionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.transaction_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.index();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdNew(env: JNIEnv, _: JObject, transaction_id_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let transaction_id_jrptr = transaction_id_ptr.rptr(&env)?;
    let transaction_id = transaction_id_jrptr.typed_ref::<TransactionHash>()?;
    let index = u32::try_from_jlong(index_jlong)?;
    let result = GovernanceActionId::new(transaction_id, index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionIds>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = GovernanceActionIds::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = GovernanceActionIds::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, governance_action_id_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionIds>()?;
    let governance_action_id_jrptr = governance_action_id_ptr.rptr(&env)?;
    let governance_action_id = governance_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    self_rptr.add(governance_action_id);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionIds>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1governanceActionIdsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<GovernanceActionIds>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = HardForkInitiationAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = HardForkInitiationAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = HardForkInitiationAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionGovActionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_rptr.gov_action_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_rptr.protocol_version();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionNew(env: JNIEnv, _: JObject, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HardForkInitiationAction::new(protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hardForkInitiationActionNewWithActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let protocol_version_jrptr = protocol_version_ptr.rptr(&env)?;
    let protocol_version = protocol_version_jrptr.typed_ref::<ProtocolVersion>()?;
    let result = HardForkInitiationAction::new_with_action_id(gov_action_id, protocol_version);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Header::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Header::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Header::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerHeaderBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodySignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerNew(env: JNIEnv, _: JObject, header_body_ptr: JRPtr, body_signature_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = HeaderBody::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = HeaderBody::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = HeaderBody::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyBlockNumber(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodySlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodySlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyPrevHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyIssuerVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyVrfVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyHasNonceAndLeaderVrf(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.has_nonce_and_leader_vrf();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyNonceVrfOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyLeaderVrfOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyHasVrfResult(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<HeaderBody>()?;
    let result = self_rptr.has_vrf_result();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyVrfResultOrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyBlockBodyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyOperationalCert(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyNew(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_jlong: jlong, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyNewWithPrevHash(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_jlong: jlong, prev_hash_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyNewHeaderbody(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1headerBodyNewHeaderbodyWithPrevHash(env: JNIEnv, _: JObject, block_number_jlong: jlong, slot_ptr: JRPtr, prev_hash_ptr: JRPtr, issuer_vkey_ptr: JRPtr, vrf_vkey_ptr: JRPtr, vrf_result_ptr: JRPtr, block_body_size_jlong: jlong, block_body_hash_ptr: JRPtr, operational_cert_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1infoActionNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = InfoAction::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Int::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Int::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Int::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intNew(env: JNIEnv, _: JObject, x_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intNewNegative(env: JNIEnv, _: JObject, x_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intNewI32(env: JNIEnv, _: JObject, x_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let x = i32::try_from_jlong(x_jlong)?;
    let result = Int::new_i32(x);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intIsPositive(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.is_positive();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intAsPositive(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intAsNegative(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intAsI32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intAsI32OrNothing(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intAsI32OrFail(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intToStr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1intFromStr(env: JNIEnv, _: JObject, string_str: JString) -> jobject {
  handle_exception_result(|| { 
    let string = string_str.string(&env)?;
    let result = Int::from_str(&string).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4ToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4FromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ipv4::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4ToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4FromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ipv4::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4ToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4FromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ipv4::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4New(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Ipv4::new(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv4Ip(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6ToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6FromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Ipv6::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6ToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6FromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Ipv6::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6ToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6FromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Ipv6::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6New(env: JNIEnv, _: JObject, data_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let result = Ipv6::new(data).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1ipv6Ip(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESSignatureToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESSignatureFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = KESSignature::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = KESVKey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = KESVKey::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1kESVKeyFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = KESVKey::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Language::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Language::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Language::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageNewPlutusV1(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v1();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageNewPlutusV2(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v2();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageNewPlutusV3(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v3();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languageKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languagesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Languages::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languagesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languagesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languagesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1languagesList(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Languages::list();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1legacyDaedalusPrivateKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = LegacyDaedalusPrivateKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1legacyDaedalusPrivateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1legacyDaedalusPrivateKeyChaincode(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1linearFeeConstant(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1linearFeeCoefficient(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1linearFeeNew(env: JNIEnv, _: JObject, coefficient_ptr: JRPtr, constant_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MIRToStakeCredentials::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MIRToStakeCredentials::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MIRToStakeCredentials::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MIRToStakeCredentials::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, cred_ptr: JRPtr, delta_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<Credential>()?;
    let delta_jrptr = delta_ptr.rptr(&env)?;
    let delta = delta_jrptr.typed_ref::<Int>()?;
    let result = self_rptr.insert(cred, delta);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, cred_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<Credential>()?;
    let result = self_rptr.get(cred);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mIRToStakeCredentialsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1malformedAddressOriginalBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MalformedAddress>()?;
    let result = self_rptr.original_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1malformedAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MalformedAddress>()?;
    let result = self_rptr.to_address();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1malformedAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let addr_jrptr = addr_ptr.rptr(&env)?;
    let addr = addr_jrptr.typed_ref::<Address>()?;
    let result = MalformedAddress::from_address(addr);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MetadataList::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MetadataList::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MetadataList::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataListAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MetadataMap::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MetadataMap::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MetadataMap::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapInsertStr(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_str: JString, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapInsertI32(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_jlong: jlong, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapGetStr(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapGetI32(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapHas(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MetadataMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_rptr.has(key);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1metadataMapKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Mint::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Mint::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Mint::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Mint::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintNewFromEntry(env: JNIEnv, _: JObject, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAsPositiveMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAsNegativeMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MintAssets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsNewFromEntry(env: JNIEnv, _: JObject, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<Int>()?;
    let result = MintAssets::new_from_entry(key, value).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintAssets>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<AssetName>()?;
    let value = value_ptr.rptr(&env)?.typed_ref::<Int>()?.clone();
    let result = self_rptr.insert(key, value).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintAssetsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MintBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderAddAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<MintWitness>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    self_rptr.add_asset(mint, asset_name, amount).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderSetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let mint_jrptr = mint_ptr.rptr(&env)?;
    let mint = mint_jrptr.typed_ref::<MintWitness>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    self_rptr.set_asset(mint, asset_name, amount).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.build().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderGetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderGetRedeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.get_redeemers().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintBuilderHasNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintBuilder>()?;
    let result = self_rptr.has_native_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintWitnessNewNativeScript(env: JNIEnv, _: JObject, native_script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let native_script_jrptr = native_script_ptr.rptr(&env)?;
    let native_script = native_script_jrptr.typed_ref::<NativeScriptSource>()?;
    let result = MintWitness::new_native_script(native_script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintWitnessNewPlutusScript(env: JNIEnv, _: JObject, plutus_script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintsAssets>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MintsAssets::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MintsAssets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_assets_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintsAssets>()?;
    let mint_assets_jrptr = mint_assets_ptr.rptr(&env)?;
    let mint_assets = mint_assets_jrptr.typed_ref::<MintAssets>()?;
    self_rptr.add(mint_assets);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintsAssets>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1mintsAssetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MintsAssets>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MoveInstantaneousReward::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MoveInstantaneousReward::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MoveInstantaneousReward::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardNewToOtherPot(env: JNIEnv, _: JObject, pot_jint: jint, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardNewToStakeCreds(env: JNIEnv, _: JObject, pot_jint: jint, amounts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardPot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardAsToOtherPot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardAsToStakeCreds(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MoveInstantaneousRewardsCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MoveInstantaneousRewardsCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MoveInstantaneousRewardsCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertMoveInstantaneousReward(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1moveInstantaneousRewardsCertNew(env: JNIEnv, _: JObject, move_instantaneous_reward_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MultiAsset::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MultiAsset::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MultiAsset::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = MultiAsset::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, assets_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetSetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, asset_name_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<MultiAsset>()?;
    let policy_id_jrptr = policy_id_ptr.rptr(&env)?;
    let policy_id = policy_id_jrptr.typed_ref::<ScriptHash>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<BigNum>()?;
    let result = self_rptr.set_asset(policy_id, asset_name, value);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetGetAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_id_ptr: JRPtr, asset_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiAssetSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_ma_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = MultiHostName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = MultiHostName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = MultiHostName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameDnsName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1multiHostNameNew(env: JNIEnv, _: JObject, dns_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NativeScript::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NativeScript::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NativeScript::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewScriptPubkey(env: JNIEnv, _: JObject, script_pubkey_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewScriptAll(env: JNIEnv, _: JObject, script_all_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewScriptAny(env: JNIEnv, _: JObject, script_any_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewScriptNOfK(env: JNIEnv, _: JObject, script_n_of_k_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewTimelockStart(env: JNIEnv, _: JObject, timelock_start_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptNewTimelockExpiry(env: JNIEnv, _: JObject, timelock_expiry_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsScriptPubkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsScriptAll(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsScriptAny(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsScriptNOfK(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsTimelockStart(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptAsTimelockExpiry(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptGetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptSourceNew(env: JNIEnv, _: JObject, script_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<NativeScript>()?;
    let result = NativeScriptSource::new(script);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptSourceNewRefInput(env: JNIEnv, _: JObject, script_hash_ptr: JRPtr, input_ptr: JRPtr, script_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let script_size = usize::try_from_jlong(script_size_jlong)?;
    let result = NativeScriptSource::new_ref_input(script_hash, input, script_size);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptSourceSetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_hashes_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScriptSource>()?;
    let key_hashes_jrptr = key_hashes_ptr.rptr(&env)?;
    let key_hashes = key_hashes_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    self_rptr.set_required_signers(key_hashes);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptSourceGetRefScriptSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScriptSource>()?;
    let result = self_rptr.get_ref_script_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NativeScripts::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NativeScripts::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NativeScripts::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NativeScripts>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nativeScriptsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NativeScripts::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NetworkId::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NetworkId::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NetworkId::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdTestnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkId::testnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdMainnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkId::mainnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkIdKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoNew(env: JNIEnv, _: JObject, network_id_jlong: jlong, protocol_magic_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoProtocolMagic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoTestnetPreview(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preview();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoTestnetPreprod(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preprod();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1networkInfoMainnet(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NetworkInfo::mainnet();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NewConstitutionAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NewConstitutionAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NewConstitutionAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionGovActionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.gov_action_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionConstitution(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.constitution();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionNew(env: JNIEnv, _: JObject, constitution_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let constitution_jrptr = constitution_ptr.rptr(&env)?;
    let constitution = constitution_jrptr.typed_ref::<Constitution>()?;
    let result = NewConstitutionAction::new(constitution);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionNewWithActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr, constitution_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let constitution_jrptr = constitution_ptr.rptr(&env)?;
    let constitution = constitution_jrptr.typed_ref::<Constitution>()?;
    let result = NewConstitutionAction::new_with_action_id(gov_action_id, constitution);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1newConstitutionActionHasScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_rptr.has_script_hash();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = NoConfidenceAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = NoConfidenceAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = NoConfidenceAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionGovActionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_rptr.gov_action_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = NoConfidenceAction::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1noConfidenceActionNewWithActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = NoConfidenceAction::new_with_action_id(gov_action_id);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Nonce::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Nonce::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Nonce::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceNewIdentity(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Nonce::new_identity();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceNewFromHash(env: JNIEnv, _: JObject, hash_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let hash = env.convert_byte_array(hash_jarray).into_result()?;
    let result = Nonce::new_from_hash(hash).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1nonceGetHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = OperationalCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = OperationalCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = OperationalCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertHotVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertSequenceNumber(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertKesPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertSigma(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1operationalCertNew(env: JNIEnv, _: JObject, hot_vkey_ptr: JRPtr, sequence_number_jlong: jlong, kes_period_jlong: jlong, sigma_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1outputDatumNewDataHash(env: JNIEnv, _: JObject, data_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let data_hash_jrptr = data_hash_ptr.rptr(&env)?;
    let data_hash = data_hash_jrptr.typed_ref::<DataHash>()?;
    let result = OutputDatum::new_data_hash(data_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1outputDatumNewData(env: JNIEnv, _: JObject, data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let data_jrptr = data_ptr.rptr(&env)?;
    let data = data_jrptr.typed_ref::<PlutusData>()?;
    let result = OutputDatum::new_data(data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1outputDatumDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OutputDatum>()?;
    let result = self_rptr.data_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1outputDatumData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<OutputDatum>()?;
    let result = self_rptr.data();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ParameterChangeAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ParameterChangeAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ParameterChangeAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionGovActionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.gov_action_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionProtocolParamUpdates(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.protocol_param_updates();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionPolicyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_rptr.policy_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionNew(env: JNIEnv, _: JObject, protocol_param_updates_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let protocol_param_updates_jrptr = protocol_param_updates_ptr.rptr(&env)?;
    let protocol_param_updates = protocol_param_updates_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = ParameterChangeAction::new(protocol_param_updates);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionNewWithActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr, protocol_param_updates_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let protocol_param_updates_jrptr = protocol_param_updates_ptr.rptr(&env)?;
    let protocol_param_updates = protocol_param_updates_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = ParameterChangeAction::new_with_action_id(gov_action_id, protocol_param_updates);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionNewWithPolicyHash(env: JNIEnv, _: JObject, protocol_param_updates_ptr: JRPtr, policy_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let protocol_param_updates_jrptr = protocol_param_updates_ptr.rptr(&env)?;
    let protocol_param_updates = protocol_param_updates_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let policy_hash_jrptr = policy_hash_ptr.rptr(&env)?;
    let policy_hash = policy_hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = ParameterChangeAction::new_with_policy_hash(protocol_param_updates, policy_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1parameterChangeActionNewWithPolicyHashAndActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr, protocol_param_updates_ptr: JRPtr, policy_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let protocol_param_updates_jrptr = protocol_param_updates_ptr.rptr(&env)?;
    let protocol_param_updates = protocol_param_updates_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let policy_hash_jrptr = policy_hash_ptr.rptr(&env)?;
    let policy_hash = policy_hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = ParameterChangeAction::new_with_policy_hash_and_action_id(gov_action_id, protocol_param_updates, policy_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusData::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusData::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewConstrPlutusData(env: JNIEnv, _: JObject, constr_plutus_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewEmptyConstrPlutusData(env: JNIEnv, _: JObject, alternative_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewSingleValueConstrPlutusData(env: JNIEnv, _: JObject, alternative_ptr: JRPtr, plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let alternative_jrptr = alternative_ptr.rptr(&env)?;
    let alternative = alternative_jrptr.typed_ref::<BigNum>()?;
    let plutus_data_jrptr = plutus_data_ptr.rptr(&env)?;
    let plutus_data = plutus_data_jrptr.typed_ref::<PlutusData>()?;
    let result = PlutusData::new_single_value_constr_plutus_data(alternative, plutus_data);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewMap(env: JNIEnv, _: JObject, map_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewList(env: JNIEnv, _: JObject, list_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewInteger(env: JNIEnv, _: JObject, integer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataNewBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusData::new_bytes(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataAsConstrPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataAsMap(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataAsList(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataAsInteger(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataFromJson(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusDataFromAddress(env: JNIEnv, _: JObject, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = PlutusData::from_address(address).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusList::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusList::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusList::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusListAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusMap::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusMap::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusMap::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, values_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMap>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<PlutusData>()?;
    let values_jrptr = values_ptr.rptr(&env)?;
    let values = values_jrptr.typed_ref::<PlutusMapValues>()?;
    let result = self_rptr.insert(key, values);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapValuesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusMapValues::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapValuesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMapValues>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapValuesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMapValues>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusMapValuesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusMapValues>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<PlutusData>()?;
    self_rptr.add(elem);
    Ok(JObject::null())
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusScript::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptNew(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::new(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptNewV2(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::new_v2(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptNewV3(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::new_v3(bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptNewWithVersion(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray, language_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromBytesV2(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::from_bytes_v2(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromBytesV3(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScript::from_bytes_v3(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromBytesWithVersion(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray, language_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptFromHexWithVersion(env: JNIEnv, _: JObject, hex_str_str: JString, language_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptLanguageVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptSourceNew(env: JNIEnv, _: JObject, script_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptSourceNewRefInput(env: JNIEnv, _: JObject, script_hash_ptr: JRPtr, input_ptr: JRPtr, lang_ver_ptr: JRPtr, script_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let script_hash_jrptr = script_hash_ptr.rptr(&env)?;
    let script_hash = script_hash_jrptr.typed_ref::<ScriptHash>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let lang_ver_jrptr = lang_ver_ptr.rptr(&env)?;
    let lang_ver = lang_ver_jrptr.typed_ref::<Language>()?;
    let script_size = usize::try_from_jlong(script_size_jlong)?;
    let result = PlutusScriptSource::new_ref_input(script_hash, input, lang_ver, script_size);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptSourceSetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_hashes_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScriptSource>()?;
    let key_hashes_jrptr = key_hashes_ptr.rptr(&env)?;
    let key_hashes = key_hashes_jrptr.typed_ref::<Ed25519KeyHashes>()?;
    self_rptr.set_required_signers(key_hashes);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptSourceGetRefScriptSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PlutusScriptSource>()?;
    let result = self_rptr.get_ref_script_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PlutusScripts::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PlutusScripts::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PlutusScripts::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusScripts::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusScriptsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessNew(env: JNIEnv, _: JObject, script_ptr: JRPtr, datum_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessNewWithRef(env: JNIEnv, _: JObject, script_ptr: JRPtr, datum_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessNewWithoutDatum(env: JNIEnv, _: JObject, script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessNewWithRefWithoutDatum(env: JNIEnv, _: JObject, script_ptr: JRPtr, redeemer_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessDatum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessRedeemer(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PlutusWitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1plutusWitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerNew(env: JNIEnv, _: JObject, slot_jlong: jlong, tx_index_jlong: jlong, cert_index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerNewPointer(env: JNIEnv, _: JObject, slot_ptr: JRPtr, tx_index_ptr: JRPtr, cert_index_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerSlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerTxIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerCertIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerSlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerTxIndexBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerCertIndexBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr, stake_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<Credential>()?;
    let stake_jrptr = stake_ptr.rptr(&env)?;
    let stake = stake_jrptr.typed_ref::<Pointer>()?;
    let result = PointerAddress::new(network, payment, stake);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressStakePointer(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1pointerAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PointerAddress>()?;
    let result = self_rptr.network_id();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolMetadata::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolMetadata::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolMetadata::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataUrl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataPoolMetadataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataNew(env: JNIEnv, _: JObject, url_ptr: JRPtr, pool_metadata_hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolMetadataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = PoolMetadataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolMetadataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = PoolMetadataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolParams::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolParams::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolParams::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsOperator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsVrfKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsPledge(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsCost(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsMargin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsRewardAccount(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsPoolOwners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsRelays(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsPoolMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsNew(env: JNIEnv, _: JObject, operator_ptr: JRPtr, vrf_keyhash_ptr: JRPtr, pledge_ptr: JRPtr, cost_ptr: JRPtr, margin_ptr: JRPtr, reward_account_ptr: JRPtr, pool_owners_ptr: JRPtr, relays_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolParamsNewWithPoolMetadata(env: JNIEnv, _: JObject, operator_ptr: JRPtr, vrf_keyhash_ptr: JRPtr, pledge_ptr: JRPtr, cost_ptr: JRPtr, margin_ptr: JRPtr, reward_account_ptr: JRPtr, pool_owners_ptr: JRPtr, relays_ptr: JRPtr, pool_metadata_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolRegistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolRegistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolRegistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationPoolParams(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRegistrationNew(env: JNIEnv, _: JObject, pool_params_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolRetirement::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolRetirement::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolRetirement::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolRetirementNew(env: JNIEnv, _: JObject, pool_keyhash_ptr: JRPtr, epoch_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PoolVotingThresholds::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PoolVotingThresholds::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = PoolVotingThresholds::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsNew(env: JNIEnv, _: JObject, motion_no_confidence_ptr: JRPtr, committee_normal_ptr: JRPtr, committee_no_confidence_ptr: JRPtr, hard_fork_initiation_ptr: JRPtr, security_relevant_threshold_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let motion_no_confidence_jrptr = motion_no_confidence_ptr.rptr(&env)?;
    let motion_no_confidence = motion_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    let committee_normal_jrptr = committee_normal_ptr.rptr(&env)?;
    let committee_normal = committee_normal_jrptr.typed_ref::<UnitInterval>()?;
    let committee_no_confidence_jrptr = committee_no_confidence_ptr.rptr(&env)?;
    let committee_no_confidence = committee_no_confidence_jrptr.typed_ref::<UnitInterval>()?;
    let hard_fork_initiation_jrptr = hard_fork_initiation_ptr.rptr(&env)?;
    let hard_fork_initiation = hard_fork_initiation_jrptr.typed_ref::<UnitInterval>()?;
    let security_relevant_threshold_jrptr = security_relevant_threshold_ptr.rptr(&env)?;
    let security_relevant_threshold = security_relevant_threshold_jrptr.typed_ref::<UnitInterval>()?;
    let result = PoolVotingThresholds::new(motion_no_confidence, committee_normal, committee_no_confidence, hard_fork_initiation, security_relevant_threshold);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsMotionNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.motion_no_confidence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsCommitteeNormal(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.committee_normal();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsCommitteeNoConfidence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.committee_no_confidence();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsHardForkInitiation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.hard_fork_initiation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1poolVotingThresholdsSecurityRelevantThreshold(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_rptr.security_relevant_threshold();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyToPublic(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyGenerateEd25519(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyGenerateEd25519extended(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519extended().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = PrivateKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyFromExtendedBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PrivateKey::from_extended_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyFromNormalBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PrivateKey::from_normal_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeySign(env: JNIEnv, _: JObject, self_ptr: JRPtr, message_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1privateKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PrivateKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProposedProtocolParameterUpdates::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProposedProtocolParameterUpdates::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProposedProtocolParameterUpdates::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ProposedProtocolParameterUpdates::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1proposedProtocolParameterUpdatesKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProtocolParamUpdate::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProtocolParamUpdate::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProtocolParamUpdate::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMinfeeA(env: JNIEnv, _: JObject, self_ptr: JRPtr, minfee_a_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMinfeeA(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMinfeeB(env: JNIEnv, _: JObject, self_ptr: JRPtr, minfee_b_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMinfeeB(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_body_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxBlockBodySize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxBlockHeaderSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_header_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxBlockHeaderSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetPoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdatePoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_epoch_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetNOpt(env: JNIEnv, _: JObject, self_ptr: JRPtr, n_opt_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateNOpt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetPoolPledgeInfluence(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_pledge_influence_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdatePoolPledgeInfluence(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetExpansionRate(env: JNIEnv, _: JObject, self_ptr: JRPtr, expansion_rate_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateExpansionRate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetTreasuryGrowthRate(env: JNIEnv, _: JObject, self_ptr: JRPtr, treasury_growth_rate_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateTreasuryGrowthRate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateD(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateExtraEntropy(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr, protocol_version_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateProtocolVersion(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMinPoolCost(env: JNIEnv, _: JObject, self_ptr: JRPtr, min_pool_cost_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMinPoolCost(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetAdaPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, ada_per_utxo_byte_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateAdaPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetCostModels(env: JNIEnv, _: JObject, self_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateCostModels(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetExecutionCosts(env: JNIEnv, _: JObject, self_ptr: JRPtr, execution_costs_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateExecutionCosts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxTxExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_ex_units_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxTxExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxBlockExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_block_ex_units_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxBlockExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_value_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetCollateralPercentage(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_percentage_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateCollateralPercentage(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMaxCollateralInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_collateral_inputs_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMaxCollateralInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetPoolVotingThresholds(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_voting_thresholds_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_voting_thresholds_jrptr = pool_voting_thresholds_ptr.rptr(&env)?;
    let pool_voting_thresholds = pool_voting_thresholds_jrptr.typed_ref::<PoolVotingThresholds>()?;
    self_rptr.set_pool_voting_thresholds(pool_voting_thresholds);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdatePoolVotingThresholds(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.pool_voting_thresholds();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetDrepVotingThresholds(env: JNIEnv, _: JObject, self_ptr: JRPtr, drep_voting_thresholds_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_voting_thresholds_jrptr = drep_voting_thresholds_ptr.rptr(&env)?;
    let drep_voting_thresholds = drep_voting_thresholds_jrptr.typed_ref::<DRepVotingThresholds>()?;
    self_rptr.set_drep_voting_thresholds(drep_voting_thresholds);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateDrepVotingThresholds(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.drep_voting_thresholds();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetMinCommitteeSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, min_committee_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let min_committee_size = u32::try_from_jlong(min_committee_size_jlong)?;
    self_rptr.set_min_committee_size(min_committee_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateMinCommitteeSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.min_committee_size();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetCommitteeTermLimit(env: JNIEnv, _: JObject, self_ptr: JRPtr, committee_term_limit_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let committee_term_limit = u32::try_from_jlong(committee_term_limit_jlong)?;
    self_rptr.set_committee_term_limit(committee_term_limit);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateCommitteeTermLimit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.committee_term_limit();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetGovernanceActionValidityPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr, governance_action_validity_period_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let governance_action_validity_period = u32::try_from_jlong(governance_action_validity_period_jlong)?;
    self_rptr.set_governance_action_validity_period(governance_action_validity_period);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateGovernanceActionValidityPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.governance_action_validity_period();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetGovernanceActionDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, governance_action_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let governance_action_deposit_jrptr = governance_action_deposit_ptr.rptr(&env)?;
    let governance_action_deposit = governance_action_deposit_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_governance_action_deposit(governance_action_deposit);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateGovernanceActionDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.governance_action_deposit();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetDrepDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, drep_deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_deposit_jrptr = drep_deposit_ptr.rptr(&env)?;
    let drep_deposit = drep_deposit_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_drep_deposit(drep_deposit);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateDrepDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.drep_deposit();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetDrepInactivityPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr, drep_inactivity_period_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_inactivity_period = u32::try_from_jlong(drep_inactivity_period_jlong)?;
    self_rptr.set_drep_inactivity_period(drep_inactivity_period);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateDrepInactivityPeriod(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.drep_inactivity_period();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateSetRefScriptCoinsPerByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, ref_script_coins_per_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let ref_script_coins_per_byte_jrptr = ref_script_coins_per_byte_ptr.rptr(&env)?;
    let ref_script_coins_per_byte = ref_script_coins_per_byte_jrptr.typed_ref::<UnitInterval>()?;
    self_rptr.set_ref_script_coins_per_byte(ref_script_coins_per_byte);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateRefScriptCoinsPerByte(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_rptr.ref_script_coins_per_byte();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolParamUpdateNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ProtocolParamUpdate::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ProtocolVersion::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ProtocolVersion::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ProtocolVersion::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionMajor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionMinor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1protocolVersionNew(env: JNIEnv, _: JObject, major_jlong: jlong, minor_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyFromBech32(env: JNIEnv, _: JObject, bech32_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech32_str = bech32_str_str.string(&env)?;
    let result = PublicKey::from_bech32(&bech32_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = PublicKey::from_bytes(&bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyVerify(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_jarray: jbyteArray, signature_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<PublicKey>()?;
    let data = env.convert_byte_array(data_jarray).into_result()?;
    let signature_jrptr = signature_ptr.rptr(&env)?;
    let signature = signature_jrptr.typed_ref::<Ed25519Signature>()?;
    let result = self_rptr.verify(&data, signature);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = PublicKey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = PublicKeys::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeysSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1publicKeysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Redeemer::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Redeemer::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Redeemer::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTag(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerNew(env: JNIEnv, _: JObject, tag_ptr: JRPtr, index_ptr: JRPtr, data_ptr: JRPtr, ex_units_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = RedeemerTag::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = RedeemerTag::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = RedeemerTag::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewSpend(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_spend();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewMint(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_mint();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewCert(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_cert();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewReward(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_reward();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewVote(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_vote();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagNewVotingProposal(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_voting_proposal();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemerTagKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Redeemers::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Redeemers::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Redeemers::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Redeemers::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1redeemersTotalExUnits(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Relay::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Relay::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Relay::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayNewSingleHostAddr(env: JNIEnv, _: JObject, single_host_addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayNewSingleHostName(env: JNIEnv, _: JObject, single_host_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayNewMultiHostName(env: JNIEnv, _: JObject, multi_host_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayAsSingleHostAddr(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayAsSingleHostName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relayAsMultiHostName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Relays::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Relays::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Relays::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Relays::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1relaysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressNew(env: JNIEnv, _: JObject, network_jlong: jlong, payment_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let network = u8::try_from_jlong(network_jlong)?;
    let payment_jrptr = payment_ptr.rptr(&env)?;
    let payment = payment_jrptr.typed_ref::<Credential>()?;
    let result = RewardAddress::new(network, payment);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressPaymentCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressToAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressFromAddress(env: JNIEnv, _: JObject, addr_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<RewardAddress>()?;
    let result = self_rptr.network_id();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = RewardAddresses::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = RewardAddresses::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = RewardAddresses::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = RewardAddresses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1rewardAddressesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptAll::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptAll::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptAll::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAllNew(env: JNIEnv, _: JObject, native_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptAny::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptAny::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptAny::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptAnyNew(env: JNIEnv, _: JObject, native_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptDataHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = ScriptDataHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptDataHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = ScriptDataHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = ScriptHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = ScriptHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptHashes::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptHashes::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptHashes::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = ScriptHashes::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptHashesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptNOfK::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptNOfK::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptNOfK::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKN(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptNOfKNew(env: JNIEnv, _: JObject, n_jlong: jlong, native_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptPubkey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptPubkey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptPubkey::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyAddrKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptPubkeyNew(env: JNIEnv, _: JObject, addr_keyhash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = ScriptRef::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = ScriptRef::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = ScriptRef::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefNewNativeScript(env: JNIEnv, _: JObject, native_script_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefNewPlutusScript(env: JNIEnv, _: JObject, plutus_script_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefIsNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.is_native_script();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefIsPlutusScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.is_plutus_script();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefPlutusScript(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1scriptRefToUnwrappedBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<ScriptRef>()?;
    let result = self_rptr.to_unwrapped_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = SingleHostAddr::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = SingleHostAddr::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = SingleHostAddr::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrPort(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrIpv4(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrIpv6(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = SingleHostAddr::new(None, None, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithPort(env: JNIEnv, _: JObject, port_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let port = u16::try_from_jlong(port_jlong)?;
    let result = SingleHostAddr::new(Some(port), None, None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithIpv4(env: JNIEnv, _: JObject, ipv4_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ipv4 = ipv4_ptr.rptr(&env)?.typed_ref::<Ipv4>()?.clone();
    let result = SingleHostAddr::new(None, Some(ipv4), None);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithPortIpv4(env: JNIEnv, _: JObject, port_jlong: jlong, ipv4_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithIpv6(env: JNIEnv, _: JObject, ipv6_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let ipv6 = ipv6_ptr.rptr(&env)?.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(None, None, Some(ipv6));
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithPortIpv6(env: JNIEnv, _: JObject, port_jlong: jlong, ipv6_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithIpv4Ipv6(env: JNIEnv, _: JObject, ipv4_ptr: JRPtr, ipv6_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostAddrNewWithPortIpv4Ipv6(env: JNIEnv, _: JObject, port_jlong: jlong, ipv4_ptr: JRPtr, ipv6_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = SingleHostName::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = SingleHostName::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = SingleHostName::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNamePort(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameDnsName(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameNew(env: JNIEnv, _: JObject, dns_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1singleHostNameNewWithPort(env: JNIEnv, _: JObject, port_jlong: jlong, dns_name_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeAndVoteDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeAndVoteDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeAndVoteDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.pool_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationDrep(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.drep();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr, drep_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let drep_jrptr = drep_ptr.rptr(&env)?;
    let drep = drep_jrptr.typed_ref::<DRep>()?;
    let result = StakeAndVoteDelegation::new(stake_credential, pool_keyhash, drep);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeAndVoteDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = StakeDelegation::new(stake_credential, pool_keyhash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeDeregistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeDeregistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeDeregistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let result = StakeDeregistration::new(stake_credential);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationNewWithExplicitRefund(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = StakeDeregistration::new_with_explicit_refund(stake_credential, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeDeregistrationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeDeregistration>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeRegistration::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeRegistration::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeRegistration::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let result = StakeRegistration::new(stake_credential);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationNewWithExplicitDeposit(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = StakeRegistration::new_with_explicit_deposit(stake_credential, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistration>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeRegistrationAndDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeRegistrationAndDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.pool_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = StakeRegistrationAndDelegation::new(stake_credential, pool_keyhash, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeRegistrationAndDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = StakeVoteRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = StakeVoteRegistrationAndDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = StakeVoteRegistrationAndDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationPoolKeyhash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.pool_keyhash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationDrep(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.drep();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, pool_keyhash_ptr: JRPtr, drep_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let pool_keyhash_jrptr = pool_keyhash_ptr.rptr(&env)?;
    let pool_keyhash = pool_keyhash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let drep_jrptr = drep_ptr.rptr(&env)?;
    let drep = drep_jrptr.typed_ref::<DRep>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = StakeVoteRegistrationAndDelegation::new(stake_credential, pool_keyhash, drep, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stakeVoteRegistrationAndDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stringsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Strings::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stringsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stringsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1stringsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TimelockExpiry::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TimelockExpiry::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TimelockExpiry::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpirySlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpirySlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryNew(env: JNIEnv, _: JObject, slot_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let slot = u32::try_from_jlong(slot_jlong)?;
    let result = TimelockExpiry::new(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockExpiryNewTimelockexpiry(env: JNIEnv, _: JObject, slot_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TimelockStart::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TimelockStart::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TimelockStart::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartSlot(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartSlotBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartNew(env: JNIEnv, _: JObject, slot_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let slot = u32::try_from_jlong(slot_jlong)?;
    let result = TimelockStart::new(slot);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1timelockStartNewTimelockstart(env: JNIEnv, _: JObject, slot_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Transaction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Transaction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Transaction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBody(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Transaction>()?;
    let result = self_rptr.is_valid();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionSetIsValid(env: JNIEnv, _: JObject, self_ptr: JRPtr, valid_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionNew(env: JNIEnv, _: JObject, body_ptr: JRPtr, witness_set_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionNewWithAuxiliaryData(env: JNIEnv, _: JObject, body_ptr: JRPtr, witness_set_ptr: JRPtr, auxiliary_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBatchLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBatchGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBatchListLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBatchListGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionBodies::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionBodies::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionBodies::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionBodies::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodiesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionBody::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionBody::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionBody::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyOutputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyFee(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyTtlBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyRemoveTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr, certs_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr, withdrawals_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetUpdate(env: JNIEnv, _: JObject, self_ptr: JRPtr, update_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyUpdate(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetAuxiliaryDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, auxiliary_data_hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyAuxiliaryDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let validity_start_interval_jrptr = validity_start_interval_ptr.rptr(&env)?;
    let validity_start_interval = validity_start_interval_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_validity_start_interval_bignum(validity_start_interval);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyMint(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, reference_inputs_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_data_hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, required_signers_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr, network_id_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyNetworkId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetVotingProcedures(env: JNIEnv, _: JObject, self_ptr: JRPtr, voting_procedures_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let voting_procedures_jrptr = voting_procedures_ptr.rptr(&env)?;
    let voting_procedures = voting_procedures_jrptr.typed_ref::<VotingProcedures>()?;
    self_rptr.set_voting_procedures(voting_procedures);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyVotingProcedures(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.voting_procedures();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetVotingProposals(env: JNIEnv, _: JObject, self_ptr: JRPtr, voting_proposals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let voting_proposals_jrptr = voting_proposals_ptr.rptr(&env)?;
    let voting_proposals = voting_proposals_jrptr.typed_ref::<VotingProposals>()?;
    self_rptr.set_voting_proposals(voting_proposals);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyVotingProposals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.voting_proposals();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetDonation(env: JNIEnv, _: JObject, self_ptr: JRPtr, donation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let donation_jrptr = donation_ptr.rptr(&env)?;
    let donation = donation_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_donation(donation);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyDonation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.donation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodySetCurrentTreasuryValue(env: JNIEnv, _: JObject, self_ptr: JRPtr, current_treasury_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let current_treasury_value_jrptr = current_treasury_value_ptr.rptr(&env)?;
    let current_treasury_value = current_treasury_value_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_current_treasury_value(current_treasury_value);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyCurrentTreasuryValue(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBody>()?;
    let result = self_rptr.current_treasury_value();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyNew(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyNewWithTtl(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr, ttl_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBodyNewTxBody(env: JNIEnv, _: JObject, inputs_ptr: JRPtr, outputs_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddInputsFrom(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr, strategy_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_collateral_return();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCollateralReturnAndTotal(env: JNIEnv, _: JObject, self_ptr: JRPtr, collateral_return_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveTotalCollateral(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_total_collateral();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetTotalCollateralAndReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, total_collateral_ptr: JRPtr, return_address_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddReferenceInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, reference_input_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddScriptReferenceInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, reference_input_ptr: JRPtr, script_size_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let reference_input_jrptr = reference_input_ptr.rptr(&env)?;
    let reference_input = reference_input_jrptr.typed_ref::<TransactionInput>()?;
    let script_size = usize::try_from_jlong(script_size_jlong)?;
    self_rptr.add_script_reference_input(reference_input, script_size);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddKeyInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddNativeScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddPlutusScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, witness_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddBootstrapInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddRegularInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_regular_input(address, input, amount).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddInputsFromAndChange(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr, strategy_jint: jint, change_config_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let strategy = strategy_jint.to_enum()?;
    let change_config_jrptr = change_config_ptr.rptr(&env)?;
    let change_config = change_config_jrptr.typed_ref::<ChangeConfig>()?;
    let result = self_rptr.add_inputs_from_and_change(inputs, strategy, change_config).into_result()?;
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddInputsFromAndChangeWithCollateralReturn(env: JNIEnv, _: JObject, self_ptr: JRPtr, inputs_ptr: JRPtr, strategy_jint: jint, change_config_ptr: JRPtr, collateral_percentage_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let inputs_jrptr = inputs_ptr.rptr(&env)?;
    let inputs = inputs_jrptr.typed_ref::<TransactionUnspentOutputs>()?;
    let strategy = strategy_jint.to_enum()?;
    let change_config_jrptr = change_config_ptr.rptr(&env)?;
    let change_config = change_config_jrptr.typed_ref::<ChangeConfig>()?;
    let collateral_percentage_jrptr = collateral_percentage_ptr.rptr(&env)?;
    let collateral_percentage = collateral_percentage_jrptr.typed_ref::<BigNum>()?;
    self_rptr.add_inputs_from_and_change_with_collateral_return(inputs, strategy, change_config, collateral_percentage).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderFeeForInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderFeeForOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetFee(env: JNIEnv, _: JObject, self_ptr: JRPtr, fee_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetTtlBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, ttl_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveTtl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_ttl();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetValidityStartIntervalBignum(env: JNIEnv, _: JObject, self_ptr: JRPtr, validity_start_interval_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveValidityStartInterval(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_validity_start_interval();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr, certs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let certs_jrptr = certs_ptr.rptr(&env)?;
    let certs = certs_jrptr.typed_ref::<Certificates>()?;
    self_rptr.set_certs(certs).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveCerts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_certs();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCertsBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, certs_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let certs_jrptr = certs_ptr.rptr(&env)?;
    let certs = certs_jrptr.typed_ref::<CertificatesBuilder>()?;
    self_rptr.set_certs_builder(certs);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr, withdrawals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<Withdrawals>()?;
    self_rptr.set_withdrawals(withdrawals).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetWithdrawalsBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, withdrawals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    self_rptr.set_withdrawals_builder(withdrawals);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetVotingBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, voting_builder_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let voting_builder_jrptr = voting_builder_ptr.rptr(&env)?;
    let voting_builder = voting_builder_jrptr.typed_ref::<VotingBuilder>()?;
    self_rptr.set_voting_builder(voting_builder);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetVotingProposalBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, voting_proposal_builder_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let voting_proposal_builder_jrptr = voting_proposal_builder_ptr.rptr(&env)?;
    let voting_proposal_builder = voting_proposal_builder_jrptr.typed_ref::<VotingProposalBuilder>()?;
    self_rptr.set_voting_proposal_builder(voting_proposal_builder);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_withdrawals();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr, auxiliary_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveAuxiliaryData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_auxiliary_data();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetMetadata(env: JNIEnv, _: JObject, self_ptr: JRPtr, metadata_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddMetadatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddJsonMetadatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddJsonMetadatumWithSchema(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, val_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetMintBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_builder_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveMintBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    self_rptr.remove_mint_builder();
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetMintBuilder(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr, mint_ptr: JRPtr, mint_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetMint(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetMintScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetMintAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, mint_assets_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let mint_assets_jrptr = mint_assets_ptr.rptr(&env)?;
    let mint_assets = mint_assets_jrptr.typed_ref::<MintAssets>()?;
    self_rptr.set_mint_asset(policy_script, mint_assets).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddMintAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    self_rptr.add_mint_asset(policy_script, asset_name, amount).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddMintAssetAndOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr, output_builder_ptr: JRPtr, output_coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddMintAssetAndOutputMinRequiredCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, policy_script_ptr: JRPtr, asset_name_ptr: JRPtr, amount_ptr: JRPtr, output_builder_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let policy_script_jrptr = policy_script_ptr.rptr(&env)?;
    let policy_script = policy_script_jrptr.typed_ref::<NativeScript>()?;
    let asset_name_jrptr = asset_name_ptr.rptr(&env)?;
    let asset_name = asset_name_jrptr.typed_ref::<AssetName>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Int>()?;
    let output_builder_jrptr = output_builder_ptr.rptr(&env)?;
    let output_builder = output_builder_jrptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    self_rptr.add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddExtraWitnessDatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, datum_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let datum_jrptr = datum_ptr.rptr(&env)?;
    let datum = datum_jrptr.typed_ref::<PlutusData>()?;
    self_rptr.add_extra_witness_datum(datum);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetExtraWitnessDatums(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_extra_witness_datums();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetDonation(env: JNIEnv, _: JObject, self_ptr: JRPtr, donation_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let donation_jrptr = donation_ptr.rptr(&env)?;
    let donation = donation_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_donation(donation);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetDonation(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_donation();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetCurrentTreasuryValue(env: JNIEnv, _: JObject, self_ptr: JRPtr, current_treasury_value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let current_treasury_value_jrptr = current_treasury_value_ptr.rptr(&env)?;
    let current_treasury_value = current_treasury_value_jrptr.typed_ref::<BigNum>()?;
    self_rptr.set_current_treasury_value(current_treasury_value).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetCurrentTreasuryValue(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let result = self_rptr.get_current_treasury_value();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderNew(env: JNIEnv, _: JObject, cfg_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetReferenceInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetExplicitInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetImplicitInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetTotalInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetTotalOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetExplicitOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderGetFeeIfSet(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddChangeIfNeeded(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let result = self_rptr.add_change_if_needed(address).into_result()?;
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddChangeIfNeededWithDatum(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, plutus_data_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let plutus_data_jrptr = plutus_data_ptr.rptr(&env)?;
    let plutus_data = plutus_data_jrptr.typed_ref::<OutputDatum>()?;
    let result = self_rptr.add_change_if_needed_with_datum(address, plutus_data).into_result()?;
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderCalcScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderSetScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderRemoveScriptDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderAddRequiredSigner(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderFullSize(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderOutputSizes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderBuildTx(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderBuildTxUnsafe(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderMinFee(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionBuilderConfigBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderFeeAlgo(env: JNIEnv, _: JObject, self_ptr: JRPtr, fee_algo_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderCoinsPerUtxoByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, coins_per_utxo_byte_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderExUnitPrices(env: JNIEnv, _: JObject, self_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderPoolDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, pool_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderKeyDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderMaxValueSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_value_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderMaxTxSize(env: JNIEnv, _: JObject, self_ptr: JRPtr, max_tx_size_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderRefScriptCoinsPerByte(env: JNIEnv, _: JObject, self_ptr: JRPtr, ref_script_coins_per_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let ref_script_coins_per_byte_jrptr = ref_script_coins_per_byte_ptr.rptr(&env)?;
    let ref_script_coins_per_byte = ref_script_coins_per_byte_jrptr.typed_ref::<UnitInterval>()?;
    let result = self_rptr.ref_script_coins_per_byte(ref_script_coins_per_byte);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderPreferPureChange(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefer_pure_change_jboolean: jboolean) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderDeduplicateExplicitRefInputsWithRegularInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr, deduplicate_explicit_ref_inputs_with_regular_inputs_jboolean: jboolean) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let deduplicate_explicit_ref_inputs_with_regular_inputs = deduplicate_explicit_ref_inputs_with_regular_inputs_jboolean.into_bool();
    let result = self_rptr.deduplicate_explicit_ref_inputs_with_regular_inputs(deduplicate_explicit_ref_inputs_with_regular_inputs);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionBuilderConfigBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = TransactionHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = TransactionHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionInput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionInput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionInput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputTransactionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputIndex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputNew(env: JNIEnv, _: JObject, transaction_id_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionInputs::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionInputs::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionInputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionInputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionInputs>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<TransactionInput>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionInputsToOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatum::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionMetadatum::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumNewMap(env: JNIEnv, _: JObject, map_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumNewList(env: JNIEnv, _: JObject, list_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumNewInt(env: JNIEnv, _: JObject, int_value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumNewBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatum::new_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumNewText(env: JNIEnv, _: JObject, text_str: JString) -> jobject {
  handle_exception_result(|| { 
    let text = text_str.string(&env)?;
    let result = TransactionMetadatum::new_text(text).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumAsMap(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumAsList(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumAsInt(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumAsBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumAsText(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionMetadatumLabels::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionMetadatumLabels::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionMetadatumLabels::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionMetadatumLabelsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionOutput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionOutput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionOutput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmount(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputSetScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ref_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputSetDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputHasPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_plutus_data();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputHasDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_data_hash();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputHasScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.has_script_ref();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputNew(env: JNIEnv, _: JObject, address_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputSerializationFormat(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TransactionOutput>()?;
    let result = self_rptr.serialization_format();
    result.map(|x| x.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmountBuilderWithValue(env: JNIEnv, _: JObject, self_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmountBuilderWithCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmountBuilderWithCoinAndAsset(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(env: JNIEnv, _: JObject, self_ptr: JRPtr, multiasset_ptr: JRPtr, data_cost_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputAmountBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionOutputBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderWithAddress(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderWithDataHash(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_hash_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderWithPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderWithScriptRef(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ref_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputBuilderNext(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionOutputs::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionOutputs::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionOutputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionOutputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionOutputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionUnspentOutput::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionUnspentOutput::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionUnspentOutput::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputNew(env: JNIEnv, _: JObject, input_ptr: JRPtr, output_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputInput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionUnspentOutputs::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionUnspentOutputs::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionUnspentOutputsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionWitnessSet::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionWitnessSet::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionWitnessSet::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetVkeys(env: JNIEnv, _: JObject, self_ptr: JRPtr, vkeys_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetVkeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, native_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetBootstraps(env: JNIEnv, _: JObject, self_ptr: JRPtr, bootstraps_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetBootstraps(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_scripts_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr, plutus_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetPlutusData(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetSetRedeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr, redeemers_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetRedeemers(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionWitnessSet::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TransactionWitnessSets::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TransactionWitnessSets::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TransactionWitnessSets::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TransactionWitnessSets::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1transactionWitnessSetsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TreasuryWithdrawals::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TreasuryWithdrawals::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<RewardAddress>()?;
    let result = self_rptr.get(key);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let key_jrptr = key_ptr.rptr(&env)?;
    let key = key_jrptr.typed_ref::<RewardAddress>()?;
    let value_jrptr = value_ptr.rptr(&env)?;
    let value = value_jrptr.typed_ref::<BigNum>()?;
    self_rptr.insert(key, value);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_rptr.keys();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = TreasuryWithdrawalsAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = TreasuryWithdrawalsAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = TreasuryWithdrawalsAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_rptr.withdrawals();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionPolicyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_rptr.policy_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionNew(env: JNIEnv, _: JObject, withdrawals_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = TreasuryWithdrawalsAction::new(withdrawals);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1treasuryWithdrawalsActionNewWithPolicyHash(env: JNIEnv, _: JObject, withdrawals_ptr: JRPtr, policy_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let withdrawals_jrptr = withdrawals_ptr.rptr(&env)?;
    let withdrawals = withdrawals_jrptr.typed_ref::<TreasuryWithdrawals>()?;
    let policy_hash_jrptr = policy_hash_ptr.rptr(&env)?;
    let policy_hash = policy_hash_jrptr.typed_ref::<ScriptHash>()?;
    let result = TreasuryWithdrawalsAction::new_with_policy_hash(withdrawals, policy_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txBuilderConstantsPlutusDefaultCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_default_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txBuilderConstantsPlutusAlonzoCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_alonzo_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txBuilderConstantsPlutusVasilCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_vasil_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txBuilderConstantsPlutusConwayCostModels(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_conway_cost_models();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = TxInputsBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddKeyInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, hash_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddNativeScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, script_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let script_jrptr = script_ptr.rptr(&env)?;
    let script = script_jrptr.typed_ref::<NativeScriptSource>()?;
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddPlutusScriptInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, witness_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddBootstrapInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<ByronAddress>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_bootstrap_input(address, input, amount);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddRegularInput(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, input_ptr: JRPtr, amount_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<TxInputsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<Address>()?;
    let input_jrptr = input_ptr.rptr(&env)?;
    let input = input_jrptr.typed_ref::<TransactionInput>()?;
    let amount_jrptr = amount_ptr.rptr(&env)?;
    let amount = amount_jrptr.typed_ref::<Value>()?;
    self_rptr.add_regular_input(address, input, amount).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderGetNativeInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderGetPlutusInputScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddRequiredSigner(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderAddRequiredSigners(env: JNIEnv, _: JObject, self_ptr: JRPtr, keys_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderTotalValue(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1txInputsBuilderInputsOption(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = URL::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = URL::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = URL::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLNew(env: JNIEnv, _: JObject, url_str: JString) -> jobject {
  handle_exception_result(|| { 
    let url = url_str.string(&env)?;
    let result = URL::new(url).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1uRLUrl(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = UnitInterval::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = UnitInterval::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = UnitInterval::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalNumerator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalDenominator(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1unitIntervalNew(env: JNIEnv, _: JObject, numerator_ptr: JRPtr, denominator_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Update::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Update::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Update::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateProposedProtocolParameterUpdates(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateEpoch(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateNew(env: JNIEnv, _: JObject, proposed_protocol_parameter_updates_ptr: JRPtr, epoch_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = UpdateCommitteeAction::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = UpdateCommitteeAction::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = UpdateCommitteeAction::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionGovActionId(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.gov_action_id();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionCommittee(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.committee();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionMembersToRemove(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_rptr.members_to_remove();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionNew(env: JNIEnv, _: JObject, committee_ptr: JRPtr, members_to_remove_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let committee_jrptr = committee_ptr.rptr(&env)?;
    let committee = committee_jrptr.typed_ref::<Committee>()?;
    let members_to_remove_jrptr = members_to_remove_ptr.rptr(&env)?;
    let members_to_remove = members_to_remove_jrptr.typed_ref::<Credentials>()?;
    let result = UpdateCommitteeAction::new(committee, members_to_remove);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1updateCommitteeActionNewWithActionId(env: JNIEnv, _: JObject, gov_action_id_ptr: JRPtr, committee_ptr: JRPtr, members_to_remove_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let committee_jrptr = committee_ptr.rptr(&env)?;
    let committee = committee_jrptr.typed_ref::<Committee>()?;
    let members_to_remove_jrptr = members_to_remove_ptr.rptr(&env)?;
    let members_to_remove = members_to_remove_jrptr.typed_ref::<Credentials>()?;
    let result = UpdateCommitteeAction::new_with_action_id(gov_action_id, committee, members_to_remove);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFCert::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VRFCert::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VRFCert::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertOutput(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertProof(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFCertNew(env: JNIEnv, _: JObject, output_jarray: jbyteArray, proof_jarray: jbyteArray) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFKeyHash::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = VRFKeyHash::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFKeyHashFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = VRFKeyHash::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VRFVKey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyToBech32(env: JNIEnv, _: JObject, self_ptr: JRPtr, prefix_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyFromBech32(env: JNIEnv, _: JObject, bech_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let bech_str = bech_str_str.string(&env)?;
    let result = VRFVKey::from_bech32(&bech_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vRFVKeyFromHex(env: JNIEnv, _: JObject, hex_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex = hex_str.string(&env)?;
    let result = VRFVKey::from_hex(&hex).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Value::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Value::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Value::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueNew(env: JNIEnv, _: JObject, coin_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueNewFromAssets(env: JNIEnv, _: JObject, multiasset_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueNewWithAssets(env: JNIEnv, _: JObject, coin_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueZero(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Value::zero();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueIsZero(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Value>()?;
    let result = self_rptr.is_zero();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueSetCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueSetMultiasset(env: JNIEnv, _: JObject, self_ptr: JRPtr, multiasset_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueCheckedAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueCheckedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueClampedSub(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1valueCompare(env: JNIEnv, _: JObject, self_ptr: JRPtr, rhs_value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VersionedBlock>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VersionedBlock::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VersionedBlock>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VersionedBlock::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VersionedBlock>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VersionedBlock::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockNew(env: JNIEnv, _: JObject, block_ptr: JRPtr, era_code_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let block = block_ptr.rptr(&env)?.typed_ref::<Block>()?.clone();
    let era_code = u32::try_from_jlong(era_code_jlong)?;
    let result = VersionedBlock::new(block, era_code);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockBlock(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VersionedBlock>()?;
    let result = self_rptr.block();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1versionedBlockEra(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VersionedBlock>()?;
    let result = self_rptr.era();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkey::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkey::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkey::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyNew(env: JNIEnv, _: JObject, pk_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeyPublicKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeysNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Vkeys::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeysLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeysGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeysAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkeywitness::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkeywitness::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkeywitness::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessNew(env: JNIEnv, _: JObject, vkey_ptr: JRPtr, signature_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessVkey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessSignature(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Vkeywitnesses::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Vkeywitnesses::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Vkeywitnesses::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Vkeywitnesses::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1vkeywitnessesAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, elem_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Vkeywitnesses>()?;
    let elem_jrptr = elem_ptr.rptr(&env)?;
    let elem = elem_jrptr.typed_ref::<Vkeywitness>()?;
    let result = self_rptr.add(elem);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VoteDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VoteDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VoteDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationDrep(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.drep();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, drep_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let drep_jrptr = drep_ptr.rptr(&env)?;
    let drep = drep_jrptr.typed_ref::<DRep>()?;
    let result = VoteDelegation::new(stake_credential, drep);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VoteRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VoteRegistrationAndDelegation::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VoteRegistrationAndDelegation::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationStakeCredential(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.stake_credential();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationDrep(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.drep();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationCoin(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.coin();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationNew(env: JNIEnv, _: JObject, stake_credential_ptr: JRPtr, drep_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let stake_credential_jrptr = stake_credential_ptr.rptr(&env)?;
    let stake_credential = stake_credential_jrptr.typed_ref::<Credential>()?;
    let drep_jrptr = drep_ptr.rptr(&env)?;
    let drep = drep_jrptr.typed_ref::<DRep>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let result = VoteRegistrationAndDelegation::new(stake_credential, drep, coin);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voteRegistrationAndDelegationHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Voter::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Voter::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Voter::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterNewConstitutionalCommitteeHotKey(env: JNIEnv, _: JObject, cred_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<Credential>()?;
    let result = Voter::new_constitutional_committee_hot_key(cred);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterNewDrep(env: JNIEnv, _: JObject, cred_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let cred_jrptr = cred_ptr.rptr(&env)?;
    let cred = cred_jrptr.typed_ref::<Credential>()?;
    let result = Voter::new_drep(cred);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterNewStakingPool(env: JNIEnv, _: JObject, key_hash_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let key_hash_jrptr = key_hash_ptr.rptr(&env)?;
    let key_hash = key_hash_jrptr.typed_ref::<Ed25519KeyHash>()?;
    let result = Voter::new_staking_pool(key_hash);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToConstitutionalCommitteeHotKey(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_constitutional_committee_hot_key();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToDrepCred(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_drep_cred();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToStakingPoolKeyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_staking_pool_key_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterHasScriptCredentials(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.has_script_credentials();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1voterToKeyHash(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.to_key_hash();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voters>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Voters::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Voters::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voters>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    self_rptr.add(voter);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voters>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votersLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<Voters>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = VotingBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr, gov_action_id_ptr: JRPtr, voting_procedure_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure_jrptr = voting_procedure_ptr.rptr(&env)?;
    let voting_procedure = voting_procedure_jrptr.typed_ref::<VotingProcedure>()?;
    self_rptr.add(voter, gov_action_id, voting_procedure).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderAddWithPlutusWitness(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr, gov_action_id_ptr: JRPtr, voting_procedure_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure_jrptr = voting_procedure_ptr.rptr(&env)?;
    let voting_procedure = voting_procedure_jrptr.typed_ref::<VotingProcedure>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    self_rptr.add_with_plutus_witness(voter, gov_action_id, voting_procedure, witness).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderAddWithNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr, gov_action_id_ptr: JRPtr, voting_procedure_ptr: JRPtr, native_script_source_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let gov_action_id_jrptr = gov_action_id_ptr.rptr(&env)?;
    let gov_action_id = gov_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure_jrptr = voting_procedure_ptr.rptr(&env)?;
    let voting_procedure = voting_procedure_jrptr.typed_ref::<VotingProcedure>()?;
    let native_script_source_jrptr = native_script_source_ptr.rptr(&env)?;
    let native_script_source = native_script_source_jrptr.typed_ref::<NativeScriptSource>()?;
    self_rptr.add_with_native_script(voter, gov_action_id, voting_procedure, native_script_source).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let result = self_rptr.get_plutus_witnesses();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderGetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let result = self_rptr.get_native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingBuilder>()?;
    let result = self_rptr.build();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedure>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VotingProcedure::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedure>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VotingProcedure::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedure>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VotingProcedure::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureNew(env: JNIEnv, _: JObject, vote_jint: jint) -> jobject {
  handle_exception_result(|| { 
    let vote = vote_jint.to_enum()?;
    let result = VotingProcedure::new(vote);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureNewWithAnchor(env: JNIEnv, _: JObject, vote_jint: jint, anchor_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let vote = vote_jint.to_enum()?;
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let result = VotingProcedure::new_with_anchor(vote, anchor);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureVoteKind(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedure>()?;
    let result = self_rptr.vote_kind();
    (result.to_i32() as jint).jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProcedureAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedure>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VotingProcedures::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VotingProcedures::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VotingProcedures::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = VotingProcedures::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr, governance_action_id_ptr: JRPtr, voting_procedure_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let governance_action_id_jrptr = governance_action_id_ptr.rptr(&env)?;
    let governance_action_id = governance_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure_jrptr = voting_procedure_ptr.rptr(&env)?;
    let voting_procedure = voting_procedure_jrptr.typed_ref::<VotingProcedure>()?;
    self_rptr.insert(voter, governance_action_id, voting_procedure);
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr, governance_action_id_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let governance_action_id_jrptr = governance_action_id_ptr.rptr(&env)?;
    let governance_action_id = governance_action_id_jrptr.typed_ref::<GovernanceActionId>()?;
    let result = self_rptr.get(voter, governance_action_id);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresGetVoters(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let result = self_rptr.get_voters();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProceduresGetGovernanceActionIdsByVoter(env: JNIEnv, _: JObject, self_ptr: JRPtr, voter_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProcedures>()?;
    let voter_jrptr = voter_ptr.rptr(&env)?;
    let voter = voter_jrptr.typed_ref::<Voter>()?;
    let result = self_rptr.get_governance_action_ids_by_voter(voter);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VotingProposal::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VotingProposal::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VotingProposal::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalGovernanceAction(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.governance_action();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalAnchor(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.anchor();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalRewardAccount(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.reward_account();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalDeposit(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.deposit();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalNew(env: JNIEnv, _: JObject, governance_action_ptr: JRPtr, anchor_ptr: JRPtr, reward_account_ptr: JRPtr, deposit_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let governance_action_jrptr = governance_action_ptr.rptr(&env)?;
    let governance_action = governance_action_jrptr.typed_ref::<GovernanceAction>()?;
    let anchor_jrptr = anchor_ptr.rptr(&env)?;
    let anchor = anchor_jrptr.typed_ref::<Anchor>()?;
    let reward_account_jrptr = reward_account_ptr.rptr(&env)?;
    let reward_account = reward_account_jrptr.typed_ref::<RewardAddress>()?;
    let deposit_jrptr = deposit_ptr.rptr(&env)?;
    let deposit = deposit_jrptr.typed_ref::<BigNum>()?;
    let result = VotingProposal::new(governance_action, anchor, reward_account, deposit);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = VotingProposalBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, proposal_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let proposal_jrptr = proposal_ptr.rptr(&env)?;
    let proposal = proposal_jrptr.typed_ref::<VotingProposal>()?;
    self_rptr.add(proposal).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderAddWithPlutusWitness(env: JNIEnv, _: JObject, self_ptr: JRPtr, proposal_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let proposal_jrptr = proposal_ptr.rptr(&env)?;
    let proposal = proposal_jrptr.typed_ref::<VotingProposal>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    self_rptr.add_with_plutus_witness(proposal, witness).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_rptr.get_plutus_witnesses();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_rptr.build();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let result = self_rptr.to_bytes();
    Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = VotingProposals::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let result = self_rptr.to_hex();
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = VotingProposals::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let result = self_rptr.to_json().into_result()?;
    result.jstring(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = VotingProposals::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = VotingProposals::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let result = self_rptr.len();
    result.into_jlong().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, index_jlong: jlong) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let index = usize::try_from_jlong(index_jlong)?;
    let result = self_rptr.get(index);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1votingProposalsAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, proposal_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<VotingProposals>()?;
    let proposal_jrptr = proposal_ptr.rptr(&env)?;
    let proposal = proposal_jrptr.typed_ref::<VotingProposal>()?;
    let result = self_rptr.add(proposal);
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsToBytes(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsFromBytes(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = Withdrawals::from_bytes(bytes).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsToHex(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsFromHex(env: JNIEnv, _: JObject, hex_str_str: JString) -> jobject {
  handle_exception_result(|| { 
    let hex_str = hex_str_str.string(&env)?;
    let result = Withdrawals::from_hex(&hex_str).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsToJson(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsFromJson(env: JNIEnv, _: JObject, json_str: JString) -> jobject {
  handle_exception_result(|| { 
    let json = json_str.string(&env)?;
    let result = Withdrawals::from_json(&json).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = Withdrawals::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsLen(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsInsert(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr, value_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsGet(env: JNIEnv, _: JObject, self_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsKeys(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderNew(env: JNIEnv, _: JObject) -> jobject {
  handle_exception_result(|| { 
    let result = WithdrawalsBuilder::new();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderAdd(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, coin_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<RewardAddress>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    self_rptr.add(address, coin).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderAddWithPlutusWitness(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, coin_ptr: JRPtr, witness_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<RewardAddress>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let witness_jrptr = witness_ptr.rptr(&env)?;
    let witness = witness_jrptr.typed_ref::<PlutusWitness>()?;
    self_rptr.add_with_plutus_witness(address, coin, witness).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderAddWithNativeScript(env: JNIEnv, _: JObject, self_ptr: JRPtr, address_ptr: JRPtr, coin_ptr: JRPtr, native_script_source_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let address_jrptr = address_ptr.rptr(&env)?;
    let address = address_jrptr.typed_ref::<RewardAddress>()?;
    let coin_jrptr = coin_ptr.rptr(&env)?;
    let coin = coin_jrptr.typed_ref::<BigNum>()?;
    let native_script_source_jrptr = native_script_source_ptr.rptr(&env)?;
    let native_script_source = native_script_source_jrptr.typed_ref::<NativeScriptSource>()?;
    self_rptr.add_with_native_script(address, coin, native_script_source).into_result()?;
    Ok(JObject::null())
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderGetPlutusWitnesses(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.get_plutus_witnesses();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderGetRefInputs(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.get_ref_inputs();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderGetNativeScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.get_native_scripts();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderGetTotalWithdrawals(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.get_total_withdrawals().into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderHasPlutusScripts(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.has_plutus_scripts();
    result.into_jboolean().jobject(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1withdrawalsBuilderBuild(env: JNIEnv, _: JObject, self_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let self_jrptr = self_ptr.rptr(&env)?;
    let self_rptr = self_jrptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_rptr.build();
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}



#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1calculateExUnitsCeilCost(env: JNIEnv, _: JObject, ex_units_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1createSendAll(env: JNIEnv, _: JObject, address_ptr: JRPtr, utxos_ptr: JRPtr, config_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1decodeArbitraryBytesFromMetadatum(env: JNIEnv, _: JObject, metadata_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1decodeMetadatumToJsonStr(env: JNIEnv, _: JObject, metadatum_ptr: JRPtr, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1decodePlutusDatumToJsonStr(env: JNIEnv, _: JObject, datum_ptr: JRPtr, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1decryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, data_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1encodeArbitraryBytesAsMetadatum(env: JNIEnv, _: JObject, bytes_jarray: jbyteArray) -> jobject {
  handle_exception_result(|| { 
    let bytes = env.convert_byte_array(bytes_jarray).into_result()?;
    let result = encode_arbitrary_bytes_as_metadatum(&bytes);
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1encodeJsonStrToMetadatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1encodeJsonStrToNativeScript(env: JNIEnv, _: JObject, json_str: JString, self_xpub_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1encodeJsonStrToPlutusDatum(env: JNIEnv, _: JObject, json_str: JString, schema_jint: jint) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1encryptWithPassword(env: JNIEnv, _: JObject, password_str: JString, salt_str: JString, nonce_str: JString, data_str: JString) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1getDeposit(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1getImplicitInput(env: JNIEnv, _: JObject, txbody_ptr: JRPtr, pool_deposit_ptr: JRPtr, key_deposit_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hashAuxiliaryData(env: JNIEnv, _: JObject, auxiliary_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hashPlutusData(env: JNIEnv, _: JObject, plutus_data_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hashScriptData(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hashScriptDataWithDatums(env: JNIEnv, _: JObject, redeemers_ptr: JRPtr, cost_models_ptr: JRPtr, datums_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1hashTransaction(env: JNIEnv, _: JObject, tx_body_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1makeDaedalusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1makeIcarusBootstrapWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, addr_ptr: JRPtr, key_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1makeVkeyWitness(env: JNIEnv, _: JObject, tx_body_hash_ptr: JRPtr, sk_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1minAdaForOutput(env: JNIEnv, _: JObject, output_ptr: JRPtr, data_cost_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1minFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, linear_fee_ptr: JRPtr) -> jobject {
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
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1minRefScriptFee(env: JNIEnv, _: JObject, total_ref_scripts_size_jlong: jlong, ref_script_coins_per_byte_ptr: JRPtr) -> jobject {
  handle_exception_result(|| { 
    let total_ref_scripts_size = usize::try_from_jlong(total_ref_scripts_size_jlong)?;
    let ref_script_coins_per_byte_jrptr = ref_script_coins_per_byte_ptr.rptr(&env)?;
    let ref_script_coins_per_byte = ref_script_coins_per_byte_jrptr.typed_ref::<UnitInterval>()?;
    let result = min_ref_script_fee(total_ref_scripts_size, ref_script_coins_per_byte).into_result()?;
    result.rptr().jptr(&env)
  })
  .jresult(&env)
}


#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_csl_1bridge_1minScriptFee(env: JNIEnv, _: JObject, tx_ptr: JRPtr, ex_unit_prices_ptr: JRPtr) -> jobject {
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


