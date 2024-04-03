use std::slice::from_raw_parts;
use super::bridge_tools::result::*;
use super::bridge_tools::string::*;
use super::bridge_tools::data::*;
use crate::js_result::*;
use crate::panic::*;
use crate::ptr::*;
use crate::enum_maps::*;
use crate::arrays::*;
use cardano_serialization_lib::Address;
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
use cardano_serialization_lib::BlockHash;
use cardano_serialization_lib::BootstrapWitness;
use cardano_serialization_lib::BootstrapWitnesses;
use cardano_serialization_lib::ByronAddress;
use cardano_serialization_lib::CborContainerType;
use cardano_serialization_lib::Certificate;
use cardano_serialization_lib::CertificateKind;
use cardano_serialization_lib::Certificates;
use cardano_serialization_lib::CertificatesBuilder;
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
use cardano_serialization_lib::DRepKind;
use cardano_serialization_lib::DataCost;
use cardano_serialization_lib::DataHash;
use cardano_serialization_lib::DatumSource;
use cardano_serialization_lib::DrepDeregistration;
use cardano_serialization_lib::DrepRegistration;
use cardano_serialization_lib::DrepUpdate;
use cardano_serialization_lib::DrepVotingThresholds;
use cardano_serialization_lib::Ed25519KeyHash;
use cardano_serialization_lib::Ed25519KeyHashes;
use cardano_serialization_lib::Ed25519Signature;
use cardano_serialization_lib::EnterpriseAddress;
use cardano_serialization_lib::ExUnitPrices;
use cardano_serialization_lib::ExUnits;
use cardano_serialization_lib::FixedTransaction;
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
use cardano_serialization_lib::TransactionIndexes;
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


#[no_mangle]
pub unsafe extern "C" fn address_from_bytes(data_data: *const u8, data_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data = from_raw_parts(data_data, data_len).to_vec();
    let result = Address::from_bytes(data).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Address::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_is_malformed(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.is_malformed();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Address::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.to_bech32(None).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_to_bech32_with_prefix(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let prefix : String = prefix_str.into_str();
    let result = self_ref.to_bech32(Some(prefix)).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn address_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = Address::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn address_network_id(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Address>()?;
    let result = self_ref.network_id().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn anchor_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Anchor>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Anchor::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Anchor>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Anchor::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Anchor>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Anchor::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_url(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Anchor>()?;
    let result = self_ref.url();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_anchor_data_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Anchor>()?;
    let result = self_ref.anchor_data_hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_new(anchor_url_rptr: RPtr, anchor_data_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let anchor_url = anchor_url_rptr.typed_ref::<URL>()?;
    let anchor_data_hash = anchor_data_hash_rptr.typed_ref::<AnchorDataHash>()?;
    let result = Anchor::new(anchor_url, anchor_data_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = AnchorDataHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AnchorDataHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AnchorDataHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = AnchorDataHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AnchorDataHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn anchor_data_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = AnchorDataHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn asset_name_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = AssetName::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = AssetName::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = AssetName::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_new(name_data: *const u8, name_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let name = from_raw_parts(name_data, name_len).to_vec();
    let result = AssetName::new(name).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_name_name(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.name();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn asset_names_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = AssetNames::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = AssetNames::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = AssetNames::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = AssetNames::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn asset_names_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AssetNames>()?;
    let elem = elem_rptr.typed_ref::<AssetName>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn assets_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Assets::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Assets::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Assets::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Assets::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let key = key_rptr.typed_ref::<AssetName>()?;
    let value = value_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let key = key_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn assets_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Assets>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = AuxiliaryData::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = AuxiliaryData::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = AuxiliaryData::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = AuxiliaryData::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_metadata(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.metadata();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_metadata(self_rptr: RPtr, metadata_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let metadata = metadata_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    self_ref.set_metadata(metadata);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.native_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_native_scripts(self_rptr: RPtr, native_scripts_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let native_scripts = native_scripts_rptr.typed_ref::<NativeScripts>()?;
    self_ref.set_native_scripts(native_scripts);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_plutus_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.plutus_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_plutus_scripts(self_rptr: RPtr, plutus_scripts_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let plutus_scripts = plutus_scripts_rptr.typed_ref::<PlutusScripts>()?;
    self_ref.set_plutus_scripts(plutus_scripts);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_prefer_alonzo_format(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.prefer_alonzo_format();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_prefer_alonzo_format(self_rptr: RPtr, prefer: bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryData>()?;
    self_ref.set_prefer_alonzo_format(prefer);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = AuxiliaryDataHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = AuxiliaryDataHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = AuxiliaryDataHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = AuxiliaryDataSet::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataSet>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_insert(self_rptr: RPtr, tx_index_long: i64, data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataSet>()?;
    let tx_index  = tx_index_long as u32;
    let data = data_rptr.typed_ref::<AuxiliaryData>()?;
    let result = self_ref.insert(tx_index, data);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_get(self_rptr: RPtr, tx_index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataSet>()?;
    let tx_index  = tx_index_long as u32;
    let result = self_ref.get(tx_index);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_set_indices(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<AuxiliaryDataSet>()?;
    let result = self_ref.indices();
    Ok::<CharPtr, String>(u32_array_to_base64(&result).into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn base_address_new(network_long: i64, payment_rptr: RPtr, stake_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let network  = network_long as u8;
    let payment = payment_rptr.typed_ref::<Credential>()?;
    let stake = stake_rptr.typed_ref::<Credential>()?;
    let result = BaseAddress::new(network, payment, stake);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn base_address_payment_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BaseAddress>()?;
    let result = self_ref.payment_cred();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn base_address_stake_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BaseAddress>()?;
    let result = self_ref.stake_cred();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn base_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BaseAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn base_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = BaseAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn big_int_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = BigInt::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = BigInt::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = BigInt::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_is_zero(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.is_zero();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_as_u64(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.as_u64();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_as_int(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.as_int();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_from_str(text_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let text: &str = text_str.into_str();
    let result = BigInt::from_str(text).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_to_str(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.to_str();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_add(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let other = other_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.add(other);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_mul(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let other = other_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.mul(other);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_one(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = BigInt::one();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_increment(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.increment();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_int_div_ceil(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigInt>()?;
    let other = other_rptr.typed_ref::<BigInt>()?;
    let result = self_ref.div_ceil(other);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn big_num_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = BigNum::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = BigNum::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = BigNum::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_from_str(string_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let string: &str = string_str.into_str();
    let result = BigNum::from_str(string).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_to_str(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.to_str();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_zero(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = BigNum::zero();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_one(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = BigNum::one();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_is_zero(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.is_zero();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_div_floor(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let other = other_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.div_floor(other);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_checked_mul(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let other = other_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.checked_mul(other).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_checked_add(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let other = other_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.checked_add(other).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_checked_sub(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let other = other_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.checked_sub(other).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_clamped_sub(self_rptr: RPtr, other_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let other = other_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.clamped_sub(other);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_compare(self_rptr: RPtr, rhs_value_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let rhs_value = rhs_value_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.compare(rhs_value);
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_less_than(self_rptr: RPtr, rhs_value_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BigNum>()?;
    let rhs_value = rhs_value_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.less_than(rhs_value);
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_max_value(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = BigNum::max_value();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn big_num_max(a_rptr: RPtr, b_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let a = a_rptr.typed_ref::<BigNum>()?;
    let b = b_rptr.typed_ref::<BigNum>()?;
    let result = BigNum::max(a, b);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_derive(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let index  = index_long as u32;
    let result = self_ref.derive(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_from_128_xprv(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = Bip32PrivateKey::from_128_xprv(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_to_128_xprv(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.to_128_xprv();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_generate_ed25519_bip32(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Bip32PrivateKey::generate_ed25519_bip32().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_to_raw_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.to_raw_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_to_public(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.to_public();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = Bip32PrivateKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.as_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_from_bech32(bech32_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech32_str: &str = bech32_str_str.into_str();
    let result = Bip32PrivateKey::from_bech32(bech32_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.to_bech32();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_from_bip39_entropy(entropy_data: *const u8, entropy_len: usize, password_data: *const u8, password_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let entropy = from_raw_parts(entropy_data, entropy_len);
    let password = from_raw_parts(password_data, password_len);
    let result = Bip32PrivateKey::from_bip39_entropy(entropy, password);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_chaincode(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.chaincode();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PrivateKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_private_key_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Bip32PrivateKey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_derive(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let index  = index_long as u32;
    let result = self_ref.derive(index).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_to_raw_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_ref.to_raw_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = Bip32PublicKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_ref.as_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_from_bech32(bech32_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech32_str: &str = bech32_str_str.into_str();
    let result = Bip32PublicKey::from_bech32(bech32_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_ref.to_bech32();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_chaincode(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_ref.chaincode();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Bip32PublicKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bip32_public_key_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Bip32PublicKey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn block_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Block::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Block::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Block::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_header(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.header();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_transaction_bodies(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.transaction_bodies();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_transaction_witness_sets(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.transaction_witness_sets();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_auxiliary_data_set(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.auxiliary_data_set();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_invalid_transactions(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Block>()?;
    let result = self_ref.invalid_transactions();
    Ok::<CharPtr, String>(u32_array_to_base64(&result).into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_new(header_rptr: RPtr, transaction_bodies_rptr: RPtr, transaction_witness_sets_rptr: RPtr, auxiliary_data_set_rptr: RPtr, invalid_transactions_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let header = header_rptr.typed_ref::<Header>()?;
    let transaction_bodies = transaction_bodies_rptr.typed_ref::<TransactionBodies>()?;
    let transaction_witness_sets = transaction_witness_sets_rptr.typed_ref::<TransactionWitnessSets>()?;
    let auxiliary_data_set = auxiliary_data_set_rptr.typed_ref::<AuxiliaryDataSet>()?;
    let invalid_transactions = base64_to_u32_array(invalid_transactions_str.into_str())?;
    let result = Block::new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_from_wrapped_bytes(data_data: *const u8, data_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data = from_raw_parts(data_data, data_len).to_vec();
    let result = Block::from_wrapped_bytes(data).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn block_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = BlockHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BlockHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BlockHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = BlockHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BlockHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn block_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = BlockHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = BootstrapWitness::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = BootstrapWitness::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = BootstrapWitness::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_vkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.vkey();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_signature(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.signature();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_chain_code(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.chain_code();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_attributes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitness>()?;
    let result = self_ref.attributes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witness_new(vkey_rptr: RPtr, signature_rptr: RPtr, chain_code_data: *const u8, chain_code_len: usize, attributes_data: *const u8, attributes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vkey = vkey_rptr.typed_ref::<Vkey>()?;
    let signature = signature_rptr.typed_ref::<Ed25519Signature>()?;
    let chain_code = from_raw_parts(chain_code_data, chain_code_len).to_vec();
    let attributes = from_raw_parts(attributes_data, attributes_len).to_vec();
    let result = BootstrapWitness::new(vkey, signature, chain_code, attributes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = BootstrapWitnesses::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitnesses>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitnesses>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn bootstrap_witnesses_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<BootstrapWitnesses>()?;
    let elem = elem_rptr.typed_ref::<BootstrapWitness>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn byron_address_to_base58(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.to_base58();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ByronAddress::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_byron_protocol_magic(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.byron_protocol_magic();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_attributes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.attributes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_network_id(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.network_id().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_from_base58(s_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let s: &str = s_str.into_str();
    let result = ByronAddress::from_base58(s).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_icarus_from_key(key_rptr: RPtr, protocol_magic_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let key = key_rptr.typed_ref::<Bip32PublicKey>()?;
    let protocol_magic  = protocol_magic_long as u32;
    let result = ByronAddress::icarus_from_key(key, protocol_magic);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_is_valid(s_str: CharPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let s: &str = s_str.into_str();
    let result = ByronAddress::is_valid(s);
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ByronAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn byron_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = ByronAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn certificate_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Certificate::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Certificate::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Certificate::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_registration(stake_registration_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_registration = stake_registration_rptr.typed_ref::<StakeRegistration>()?;
    let result = Certificate::new_stake_registration(stake_registration);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_deregistration(stake_deregistration_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_deregistration = stake_deregistration_rptr.typed_ref::<StakeDeregistration>()?;
    let result = Certificate::new_stake_deregistration(stake_deregistration);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_delegation(stake_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_delegation = stake_delegation_rptr.typed_ref::<StakeDelegation>()?;
    let result = Certificate::new_stake_delegation(stake_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_pool_registration(pool_registration_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pool_registration = pool_registration_rptr.typed_ref::<PoolRegistration>()?;
    let result = Certificate::new_pool_registration(pool_registration);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_pool_retirement(pool_retirement_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pool_retirement = pool_retirement_rptr.typed_ref::<PoolRetirement>()?;
    let result = Certificate::new_pool_retirement(pool_retirement);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_genesis_key_delegation(genesis_key_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let genesis_key_delegation = genesis_key_delegation_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = Certificate::new_genesis_key_delegation(genesis_key_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let move_instantaneous_rewards_cert = move_instantaneous_rewards_cert_rptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = Certificate::new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_committee_hot_auth(committee_hot_auth_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee_hot_auth = committee_hot_auth_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = Certificate::new_committee_hot_auth(committee_hot_auth);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_committee_cold_resign(committee_cold_resign_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee_cold_resign = committee_cold_resign_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = Certificate::new_committee_cold_resign(committee_cold_resign);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_drep_deregistration(drep_deregistration_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let drep_deregistration = drep_deregistration_rptr.typed_ref::<DrepDeregistration>()?;
    let result = Certificate::new_drep_deregistration(drep_deregistration);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_drep_registration(drep_registration_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let drep_registration = drep_registration_rptr.typed_ref::<DrepRegistration>()?;
    let result = Certificate::new_drep_registration(drep_registration);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_drep_update(drep_update_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let drep_update = drep_update_rptr.typed_ref::<DrepUpdate>()?;
    let result = Certificate::new_drep_update(drep_update);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_and_vote_delegation(stake_and_vote_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_and_vote_delegation = stake_and_vote_delegation_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = Certificate::new_stake_and_vote_delegation(stake_and_vote_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_registration_and_delegation(stake_registration_and_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_registration_and_delegation = stake_registration_and_delegation_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = Certificate::new_stake_registration_and_delegation(stake_registration_and_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_stake_vote_registration_and_delegation(stake_vote_registration_and_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_vote_registration_and_delegation = stake_vote_registration_and_delegation_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = Certificate::new_stake_vote_registration_and_delegation(stake_vote_registration_and_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_vote_delegation(vote_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vote_delegation = vote_delegation_rptr.typed_ref::<VoteDelegation>()?;
    let result = Certificate::new_vote_delegation(vote_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_new_vote_registration_and_delegation(vote_registration_and_delegation_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vote_registration_and_delegation = vote_registration_and_delegation_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = Certificate::new_vote_registration_and_delegation(vote_registration_and_delegation);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_registration(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_registration();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_deregistration(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_deregistration();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_pool_registration(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_pool_registration();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_pool_retirement(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_pool_retirement();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_genesis_key_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_genesis_key_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_move_instantaneous_rewards_cert(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_move_instantaneous_rewards_cert();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_committee_hot_auth(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_committee_hot_auth();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_committee_cold_resign(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_committee_cold_resign();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_drep_deregistration(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_drep_deregistration();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_drep_registration(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_drep_registration();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_drep_update(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_drep_update();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_and_vote_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_and_vote_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_registration_and_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_registration_and_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_stake_vote_registration_and_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_stake_vote_registration_and_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_vote_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_vote_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_as_vote_registration_and_delegation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.as_vote_registration_and_delegation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificate_has_required_script_witness(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificate>()?;
    let result = self_ref.has_required_script_witness();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn certificates_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Certificates::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Certificates::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Certificates::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Certificates::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Certificates>()?;
    let elem = elem_rptr.typed_ref::<Certificate>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn certificates_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = CertificatesBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_add(self_rptr: RPtr, cert_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let cert = cert_rptr.typed_ref::<Certificate>()?;
    self_ref.add(cert).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_add_with_plutus_witness(self_rptr: RPtr, cert_rptr: RPtr, witness_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let cert = cert_rptr.typed_ref::<Certificate>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    self_ref.add_with_plutus_witness(cert, witness).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_add_with_native_script(self_rptr: RPtr, cert_rptr: RPtr, native_script_source_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let cert = cert_rptr.typed_ref::<Certificate>()?;
    let native_script_source = native_script_source_rptr.typed_ref::<NativeScriptSource>()?;
    self_ref.add_with_native_script(cert, native_script_source).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_get_plutus_witnesses(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_ref.get_plutus_witnesses();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_get_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_ref.get_native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_get_certificates_refund(self_rptr: RPtr, pool_deposit_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.get_certificates_refund(pool_deposit, key_deposit).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_get_certificates_deposit(self_rptr: RPtr, pool_deposit_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.get_certificates_deposit(pool_deposit, key_deposit).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_has_plutus_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_ref.has_plutus_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn certificates_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CertificatesBuilder>()?;
    let result = self_ref.build();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn committee_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Committee::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Committee::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Committee::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_new(quorum_threshold_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let quorum_threshold = quorum_threshold_rptr.typed_ref::<UnitInterval>()?;
    let result = Committee::new(quorum_threshold);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_members_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let result = self_ref.members_keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_quorum_threshold(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let result = self_ref.quorum_threshold();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_add_member(self_rptr: RPtr, committee_cold_credential_rptr: RPtr, epoch_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let committee_cold_credential = committee_cold_credential_rptr.typed_ref::<Credential>()?;
    let epoch  = epoch_long as u32;
    self_ref.add_member(committee_cold_credential, epoch);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_get_member_epoch(self_rptr: RPtr, committee_cold_credential_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Committee>()?;
    let committee_cold_credential = committee_cold_credential_rptr.typed_ref::<Credential>()?;
    let result = self_ref.get_member_epoch(committee_cold_credential);
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = CommitteeColdResign::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = CommitteeColdResign::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = CommitteeColdResign::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_committee_cold_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.committee_cold_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.anchor();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_new(committee_cold_key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee_cold_key = committee_cold_key_rptr.typed_ref::<Credential>()?;
    let result = CommitteeColdResign::new(committee_cold_key);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_new_with_anchor(committee_cold_key_rptr: RPtr, anchor_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee_cold_key = committee_cold_key_rptr.typed_ref::<Credential>()?;
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let result = CommitteeColdResign::new_with_anchor(committee_cold_key, anchor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_cold_resign_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeColdResign>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = CommitteeHotAuth::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = CommitteeHotAuth::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = CommitteeHotAuth::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_committee_cold_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.committee_cold_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_committee_hot_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.committee_hot_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_new(committee_cold_key_rptr: RPtr, committee_hot_key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee_cold_key = committee_cold_key_rptr.typed_ref::<Credential>()?;
    let committee_hot_key = committee_hot_key_rptr.typed_ref::<Credential>()?;
    let result = CommitteeHotAuth::new(committee_cold_key, committee_hot_key);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn committee_hot_auth_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CommitteeHotAuth>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn constitution_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Constitution>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Constitution::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Constitution>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Constitution::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Constitution>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Constitution::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Constitution>()?;
    let result = self_ref.anchor();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_script_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Constitution>()?;
    let result = self_ref.script_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_new(anchor_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let result = Constitution::new(anchor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constitution_new_with_script_hash(anchor_rptr: RPtr, script_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let script_hash = script_hash_rptr.typed_ref::<ScriptHash>()?;
    let result = Constitution::new_with_script_hash(anchor, script_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ConstrPlutusData::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ConstrPlutusData::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_alternative(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_ref.alternative();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ConstrPlutusData>()?;
    let result = self_ref.data();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn constr_plutus_data_new(alternative_rptr: RPtr, data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let alternative = alternative_rptr.typed_ref::<BigNum>()?;
    let data = data_rptr.typed_ref::<PlutusList>()?;
    let result = ConstrPlutusData::new(alternative, data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn cost_model_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = CostModel::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = CostModel::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = CostModel::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = CostModel::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_set(self_rptr: RPtr, operation_long: i64, cost_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let operation  = operation_long as usize;
    let cost = cost_rptr.typed_ref::<Int>()?;
    let result = self_ref.set(operation, cost).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_get(self_rptr: RPtr, operation_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let operation  = operation_long as usize;
    let result = self_ref.get(operation).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn cost_model_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<CostModel>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn costmdls_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Costmdls::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Costmdls::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Costmdls::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Costmdls::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let key = key_rptr.typed_ref::<Language>()?;
    let value = value_rptr.typed_ref::<CostModel>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let key = key_rptr.typed_ref::<Language>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn costmdls_retain_language_versions(self_rptr: RPtr, languages_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Costmdls>()?;
    let languages = languages_rptr.typed_ref::<Languages>()?;
    let result = self_ref.retain_language_versions(languages);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn credential_from_keyhash(hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hash = hash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = Credential::from_keyhash(hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_from_scripthash(hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hash = hash_rptr.typed_ref::<ScriptHash>()?;
    let result = Credential::from_scripthash(hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_to_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.to_keyhash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_to_scripthash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.to_scripthash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_has_script_hash(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.has_script_hash();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Credential::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Credential::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credential>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credential_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Credential::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn credentials_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Credentials::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Credentials::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Credentials::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Credentials::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn credentials_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Credentials>()?;
    let elem = elem_rptr.typed_ref::<Credential>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DNSRecordAorAAAA::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DNSRecordAorAAAA::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DNSRecordAorAAAA::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_new(dns_name_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let dns_name : String = dns_name_str.into_str();
    let result = DNSRecordAorAAAA::new(dns_name).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_aor_a_a_a_a_record(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = self_ref.record();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DNSRecordSRV::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DNSRecordSRV::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DNSRecordSRV::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_new(dns_name_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let dns_name : String = dns_name_str.into_str();
    let result = DNSRecordSRV::new(dns_name).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_n_s_record_s_r_v_record(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DNSRecordSRV>()?;
    let result = self_ref.record();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn d_rep_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DRep::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DRep::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DRep::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_new_key_hash(key_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let key_hash = key_hash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = DRep::new_key_hash(key_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_new_script_hash(script_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_hash = script_hash_rptr.typed_ref::<ScriptHash>()?;
    let result = DRep::new_script_hash(script_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_new_always_abstain(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = DRep::new_always_abstain();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_new_always_no_confidence(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = DRep::new_always_no_confidence();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_to_key_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.to_key_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn d_rep_to_script_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DRep>()?;
    let result = self_ref.to_script_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn data_cost_new_coins_per_byte(coins_per_byte_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let coins_per_byte = coins_per_byte_rptr.typed_ref::<BigNum>()?;
    let result = DataCost::new_coins_per_byte(coins_per_byte);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_cost_coins_per_byte(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DataCost>()?;
    let result = self_ref.coins_per_byte();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn data_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DataHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DataHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DataHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = DataHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DataHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn data_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = DataHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn datum_source_new(datum_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let datum = datum_rptr.typed_ref::<PlutusData>()?;
    let result = DatumSource::new(datum);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn datum_source_new_ref_input(input_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let result = DatumSource::new_ref_input(input);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DrepDeregistration::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DrepDeregistration::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DrepDeregistration::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_voting_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.voting_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_new(voting_credential_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let voting_credential = voting_credential_rptr.typed_ref::<Credential>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = DrepDeregistration::new(voting_credential, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_deregistration_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepDeregistration>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn drep_registration_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DrepRegistration::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DrepRegistration::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DrepRegistration::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_voting_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.voting_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.anchor();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_new(voting_credential_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let voting_credential = voting_credential_rptr.typed_ref::<Credential>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = DrepRegistration::new(voting_credential, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_new_with_anchor(voting_credential_rptr: RPtr, coin_rptr: RPtr, anchor_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let voting_credential = voting_credential_rptr.typed_ref::<Credential>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let result = DrepRegistration::new_with_anchor(voting_credential, coin, anchor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_registration_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepRegistration>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn drep_update_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DrepUpdate::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DrepUpdate::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DrepUpdate::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_voting_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.voting_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.anchor();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_new(voting_credential_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let voting_credential = voting_credential_rptr.typed_ref::<Credential>()?;
    let result = DrepUpdate::new(voting_credential);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_new_with_anchor(voting_credential_rptr: RPtr, anchor_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let voting_credential = voting_credential_rptr.typed_ref::<Credential>()?;
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let result = DrepUpdate::new_with_anchor(voting_credential, anchor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_update_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepUpdate>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = DrepVotingThresholds::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = DrepVotingThresholds::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = DrepVotingThresholds::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_new(motion_no_confidence_rptr: RPtr, committee_normal_rptr: RPtr, committee_no_confidence_rptr: RPtr, update_constitution_rptr: RPtr, hard_fork_initiation_rptr: RPtr, pp_network_group_rptr: RPtr, pp_economic_group_rptr: RPtr, pp_technical_group_rptr: RPtr, pp_governance_group_rptr: RPtr, treasury_withdrawal_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let motion_no_confidence = motion_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    let committee_normal = committee_normal_rptr.typed_ref::<UnitInterval>()?;
    let committee_no_confidence = committee_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    let update_constitution = update_constitution_rptr.typed_ref::<UnitInterval>()?;
    let hard_fork_initiation = hard_fork_initiation_rptr.typed_ref::<UnitInterval>()?;
    let pp_network_group = pp_network_group_rptr.typed_ref::<UnitInterval>()?;
    let pp_economic_group = pp_economic_group_rptr.typed_ref::<UnitInterval>()?;
    let pp_technical_group = pp_technical_group_rptr.typed_ref::<UnitInterval>()?;
    let pp_governance_group = pp_governance_group_rptr.typed_ref::<UnitInterval>()?;
    let treasury_withdrawal = treasury_withdrawal_rptr.typed_ref::<UnitInterval>()?;
    let result = DrepVotingThresholds::new(motion_no_confidence, committee_normal, committee_no_confidence, update_constitution, hard_fork_initiation, pp_network_group, pp_economic_group, pp_technical_group, pp_governance_group, treasury_withdrawal);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_new_default(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = DrepVotingThresholds::new_default();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_motion_no_confidence(self_rptr: RPtr, motion_no_confidence_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let motion_no_confidence = motion_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_motion_no_confidence(motion_no_confidence);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_committee_normal(self_rptr: RPtr, committee_normal_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let committee_normal = committee_normal_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_committee_normal(committee_normal);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_committee_no_confidence(self_rptr: RPtr, committee_no_confidence_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let committee_no_confidence = committee_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_committee_no_confidence(committee_no_confidence);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_update_constitution(self_rptr: RPtr, update_constitution_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let update_constitution = update_constitution_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_update_constitution(update_constitution);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_hard_fork_initiation(self_rptr: RPtr, hard_fork_initiation_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let hard_fork_initiation = hard_fork_initiation_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_hard_fork_initiation(hard_fork_initiation);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_pp_network_group(self_rptr: RPtr, pp_network_group_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let pp_network_group = pp_network_group_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_pp_network_group(pp_network_group);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_pp_economic_group(self_rptr: RPtr, pp_economic_group_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let pp_economic_group = pp_economic_group_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_pp_economic_group(pp_economic_group);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_pp_technical_group(self_rptr: RPtr, pp_technical_group_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let pp_technical_group = pp_technical_group_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_pp_technical_group(pp_technical_group);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_pp_governance_group(self_rptr: RPtr, pp_governance_group_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let pp_governance_group = pp_governance_group_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_pp_governance_group(pp_governance_group);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_set_treasury_withdrawal(self_rptr: RPtr, treasury_withdrawal_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let treasury_withdrawal = treasury_withdrawal_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_treasury_withdrawal(treasury_withdrawal);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_motion_no_confidence(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.motion_no_confidence();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_committee_normal(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.committee_normal();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_committee_no_confidence(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.committee_no_confidence();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_update_constitution(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.update_constitution();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_hard_fork_initiation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.hard_fork_initiation();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_pp_network_group(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.pp_network_group();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_pp_economic_group(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.pp_economic_group();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_pp_technical_group(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.pp_technical_group();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_pp_governance_group(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.pp_governance_group();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn drep_voting_thresholds_treasury_withdrawal(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<DrepVotingThresholds>()?;
    let result = self_ref.treasury_withdrawal();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Ed25519KeyHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = Ed25519KeyHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = Ed25519KeyHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Ed25519KeyHashes::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Ed25519KeyHashes::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Ed25519KeyHashes::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Ed25519KeyHashes::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let elem = elem_rptr.typed_ref::<Ed25519KeyHash>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_contains(self_rptr: RPtr, elem_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let elem = elem_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = self_ref.contains(elem);
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_key_hashes_to_option(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = self_ref.to_option();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519Signature>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519Signature>()?;
    let result = self_ref.to_bech32();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ed25519Signature>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_from_bech32(bech32_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech32_str: &str = bech32_str_str.into_str();
    let result = Ed25519Signature::from_bech32(bech32_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_from_hex(input_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let input: &str = input_str.into_str();
    let result = Ed25519Signature::from_hex(input).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Ed25519Signature::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn enterprise_address_new(network_long: i64, payment_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let network  = network_long as u8;
    let payment = payment_rptr.typed_ref::<Credential>()?;
    let result = EnterpriseAddress::new(network, payment);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn enterprise_address_payment_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<EnterpriseAddress>()?;
    let result = self_ref.payment_cred();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn enterprise_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<EnterpriseAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn enterprise_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = EnterpriseAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ExUnitPrices::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ExUnitPrices::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ExUnitPrices::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_mem_price(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.mem_price();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_step_price(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.step_price();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_unit_prices_new(mem_price_rptr: RPtr, step_price_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let mem_price = mem_price_rptr.typed_ref::<UnitInterval>()?;
    let step_price = step_price_rptr.typed_ref::<UnitInterval>()?;
    let result = ExUnitPrices::new(mem_price, step_price);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ex_units_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnits>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ExUnits::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnits>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ExUnits::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnits>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ExUnits::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_mem(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnits>()?;
    let result = self_ref.mem();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_steps(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ExUnits>()?;
    let result = self_ref.steps();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ex_units_new(mem_rptr: RPtr, steps_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let mem = mem_rptr.typed_ref::<BigNum>()?;
    let steps = steps_rptr.typed_ref::<BigNum>()?;
    let result = ExUnits::new(mem, steps);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = FixedTransaction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = FixedTransaction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_new(raw_body_data: *const u8, raw_body_len: usize, raw_witness_set_data: *const u8, raw_witness_set_len: usize, is_valid: bool, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let raw_body = from_raw_parts(raw_body_data, raw_body_len);
    let raw_witness_set = from_raw_parts(raw_witness_set_data, raw_witness_set_len);
    let result = FixedTransaction::new(raw_body, raw_witness_set, is_valid).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_new_with_auxiliary(raw_body_data: *const u8, raw_body_len: usize, raw_witness_set_data: *const u8, raw_witness_set_len: usize, raw_auxiliary_data_data: *const u8, raw_auxiliary_data_len: usize, is_valid: bool, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let raw_body = from_raw_parts(raw_body_data, raw_body_len);
    let raw_witness_set = from_raw_parts(raw_witness_set_data, raw_witness_set_len);
    let raw_auxiliary_data = from_raw_parts(raw_auxiliary_data_data, raw_auxiliary_data_len);
    let result = FixedTransaction::new_with_auxiliary(raw_body, raw_witness_set, raw_auxiliary_data, is_valid).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_body(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.body();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_raw_body(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.raw_body();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_set_body(self_rptr: RPtr, raw_body_data: *const u8, raw_body_len: usize, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let raw_body = from_raw_parts(raw_body_data, raw_body_len);
    self_ref.set_body(raw_body).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_set_witness_set(self_rptr: RPtr, raw_witness_set_data: *const u8, raw_witness_set_len: usize, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let raw_witness_set = from_raw_parts(raw_witness_set_data, raw_witness_set_len);
    self_ref.set_witness_set(raw_witness_set).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_witness_set(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.witness_set();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_raw_witness_set(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.raw_witness_set();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_set_is_valid(self_rptr: RPtr, valid: bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    self_ref.set_is_valid(valid);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_is_valid(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.is_valid();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_set_auxiliary_data(self_rptr: RPtr, raw_auxiliary_data_data: *const u8, raw_auxiliary_data_len: usize, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let raw_auxiliary_data = from_raw_parts(raw_auxiliary_data_data, raw_auxiliary_data_len);
    self_ref.set_auxiliary_data(raw_auxiliary_data).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_auxiliary_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.auxiliary_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn fixed_transaction_raw_auxiliary_data(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<FixedTransaction>()?;
    let result = self_ref.raw_auxiliary_data();
    Ok::<Option<DataPtr>, String>(result.into_option())
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GeneralTransactionMetadata::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = GeneralTransactionMetadata::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GeneralTransactionMetadata::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = GeneralTransactionMetadata::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let key = key_rptr.typed_ref::<BigNum>()?;
    let value = value_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let key = key_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn general_transaction_metadata_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GenesisDelegateHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisDelegateHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisDelegateHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = GenesisDelegateHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisDelegateHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_delegate_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = GenesisDelegateHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn genesis_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GenesisHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = GenesisHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = GenesisHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GenesisHashes::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = GenesisHashes::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GenesisHashes::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = GenesisHashes::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_hashes_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisHashes>()?;
    let elem = elem_rptr.typed_ref::<GenesisHash>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GenesisKeyDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = GenesisKeyDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GenesisKeyDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_genesishash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.genesishash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_genesis_delegate_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.genesis_delegate_hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_vrf_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GenesisKeyDelegation>()?;
    let result = self_ref.vrf_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn genesis_key_delegation_new(genesishash_rptr: RPtr, genesis_delegate_hash_rptr: RPtr, vrf_keyhash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let genesishash = genesishash_rptr.typed_ref::<GenesisHash>()?;
    let genesis_delegate_hash = genesis_delegate_hash_rptr.typed_ref::<GenesisDelegateHash>()?;
    let vrf_keyhash = vrf_keyhash_rptr.typed_ref::<VRFKeyHash>()?;
    let result = GenesisKeyDelegation::new(genesishash, genesis_delegate_hash, vrf_keyhash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn governance_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GovernanceAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = GovernanceAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GovernanceAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_parameter_change_action(parameter_change_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let parameter_change_action = parameter_change_action_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = GovernanceAction::new_parameter_change_action(parameter_change_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_hard_fork_initiation_action(hard_fork_initiation_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hard_fork_initiation_action = hard_fork_initiation_action_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = GovernanceAction::new_hard_fork_initiation_action(hard_fork_initiation_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_treasury_withdrawals_action(treasury_withdrawals_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let treasury_withdrawals_action = treasury_withdrawals_action_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = GovernanceAction::new_treasury_withdrawals_action(treasury_withdrawals_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_no_confidence_action(no_confidence_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let no_confidence_action = no_confidence_action_rptr.typed_ref::<NoConfidenceAction>()?;
    let result = GovernanceAction::new_no_confidence_action(no_confidence_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_new_committee_action(new_committee_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let new_committee_action = new_committee_action_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = GovernanceAction::new_new_committee_action(new_committee_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_new_constitution_action(new_constitution_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let new_constitution_action = new_constitution_action_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = GovernanceAction::new_new_constitution_action(new_constitution_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_new_info_action(info_action_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let info_action = info_action_rptr.typed_ref::<InfoAction>()?;
    let result = GovernanceAction::new_info_action(info_action);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_parameter_change_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_parameter_change_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_hard_fork_initiation_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_hard_fork_initiation_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_treasury_withdrawals_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_treasury_withdrawals_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_no_confidence_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_no_confidence_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_new_committee_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_new_committee_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_new_constitution_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_new_constitution_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_as_info_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceAction>()?;
    let result = self_ref.as_info_action();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn governance_action_id_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = GovernanceActionId::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = GovernanceActionId::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GovernanceActionId::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_transaction_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.transaction_id();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_index(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.index();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_id_new(transaction_id_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let transaction_id = transaction_id_rptr.typed_ref::<TransactionHash>()?;
    let index  = index_long as u32;
    let result = GovernanceActionId::new(transaction_id, index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionIds>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = GovernanceActionIds::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = GovernanceActionIds::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_add(self_rptr: RPtr, governance_action_id_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionIds>()?;
    let governance_action_id = governance_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    self_ref.add(governance_action_id);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionIds>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn governance_action_ids_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<GovernanceActionIds>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = HardForkInitiationAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = HardForkInitiationAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = HardForkInitiationAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_gov_action_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_ref.gov_action_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_protocol_version(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HardForkInitiationAction>()?;
    let result = self_ref.protocol_version();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_new(protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HardForkInitiationAction::new(protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hard_fork_initiation_action_new_with_action_id(gov_action_id_rptr: RPtr, protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HardForkInitiationAction::new_with_action_id(gov_action_id, protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn header_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Header>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Header::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Header>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Header::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Header>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Header::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_header_body(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Header>()?;
    let result = self_ref.header_body();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_signature(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Header>()?;
    let result = self_ref.body_signature();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_new(header_body_rptr: RPtr, body_signature_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let header_body = header_body_rptr.typed_ref::<HeaderBody>()?;
    let body_signature = body_signature_rptr.typed_ref::<KESSignature>()?;
    let result = Header::new(header_body, body_signature);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn header_body_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = HeaderBody::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = HeaderBody::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = HeaderBody::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_block_number(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.block_number();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_slot(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.slot().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_slot_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.slot_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_prev_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.prev_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_issuer_vkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.issuer_vkey();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_vrf_vkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.vrf_vkey();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_has_nonce_and_leader_vrf(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.has_nonce_and_leader_vrf();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_nonce_vrf_or_nothing(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.nonce_vrf_or_nothing();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_leader_vrf_or_nothing(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.leader_vrf_or_nothing();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_has_vrf_result(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.has_vrf_result();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_vrf_result_or_nothing(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.vrf_result_or_nothing();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_block_body_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.block_body_size();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_block_body_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.block_body_hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_operational_cert(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.operational_cert();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_protocol_version(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<HeaderBody>()?;
    let result = self_ref.protocol_version();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_new(block_number_long: i64, slot_long: i64, issuer_vkey_rptr: RPtr, vrf_vkey_rptr: RPtr, vrf_result_rptr: RPtr, block_body_size_long: i64, block_body_hash_rptr: RPtr, operational_cert_rptr: RPtr, protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let block_number  = block_number_long as u32;
    let slot  = slot_long as u32;
    let issuer_vkey = issuer_vkey_rptr.typed_ref::<Vkey>()?;
    let vrf_vkey = vrf_vkey_rptr.typed_ref::<VRFVKey>()?;
    let vrf_result = vrf_result_rptr.typed_ref::<VRFCert>()?;
    let block_body_size  = block_body_size_long as u32;
    let block_body_hash = block_body_hash_rptr.typed_ref::<BlockHash>()?;
    let operational_cert = operational_cert_rptr.typed_ref::<OperationalCert>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new(block_number, slot, None, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_new_with_prev_hash(block_number_long: i64, slot_long: i64, prev_hash_rptr: RPtr, issuer_vkey_rptr: RPtr, vrf_vkey_rptr: RPtr, vrf_result_rptr: RPtr, block_body_size_long: i64, block_body_hash_rptr: RPtr, operational_cert_rptr: RPtr, protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let block_number  = block_number_long as u32;
    let slot  = slot_long as u32;
    let prev_hash = prev_hash_rptr.typed_ref::<BlockHash>()?.clone();
    let issuer_vkey = issuer_vkey_rptr.typed_ref::<Vkey>()?;
    let vrf_vkey = vrf_vkey_rptr.typed_ref::<VRFVKey>()?;
    let vrf_result = vrf_result_rptr.typed_ref::<VRFCert>()?;
    let block_body_size  = block_body_size_long as u32;
    let block_body_hash = block_body_hash_rptr.typed_ref::<BlockHash>()?;
    let operational_cert = operational_cert_rptr.typed_ref::<OperationalCert>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new(block_number, slot, Some(prev_hash), issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn header_body_new_headerbody(block_number_long: i64, slot_rptr: RPtr, issuer_vkey_rptr: RPtr, vrf_vkey_rptr: RPtr, vrf_result_rptr: RPtr, block_body_size_long: i64, block_body_hash_rptr: RPtr, operational_cert_rptr: RPtr, protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let block_number  = block_number_long as u32;
    let slot = slot_rptr.typed_ref::<BigNum>()?;
    let issuer_vkey = issuer_vkey_rptr.typed_ref::<Vkey>()?;
    let vrf_vkey = vrf_vkey_rptr.typed_ref::<VRFVKey>()?;
    let vrf_result = vrf_result_rptr.typed_ref::<VRFCert>()?;
    let block_body_size  = block_body_size_long as u32;
    let block_body_hash = block_body_hash_rptr.typed_ref::<BlockHash>()?;
    let operational_cert = operational_cert_rptr.typed_ref::<OperationalCert>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new_headerbody(block_number, slot, None, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn header_body_new_headerbody_with_prev_hash(block_number_long: i64, slot_rptr: RPtr, prev_hash_rptr: RPtr, issuer_vkey_rptr: RPtr, vrf_vkey_rptr: RPtr, vrf_result_rptr: RPtr, block_body_size_long: i64, block_body_hash_rptr: RPtr, operational_cert_rptr: RPtr, protocol_version_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let block_number  = block_number_long as u32;
    let slot = slot_rptr.typed_ref::<BigNum>()?;
    let prev_hash = prev_hash_rptr.typed_ref::<BlockHash>()?.clone();
    let issuer_vkey = issuer_vkey_rptr.typed_ref::<Vkey>()?;
    let vrf_vkey = vrf_vkey_rptr.typed_ref::<VRFVKey>()?;
    let vrf_result = vrf_result_rptr.typed_ref::<VRFCert>()?;
    let block_body_size  = block_body_size_long as u32;
    let block_body_hash = block_body_hash_rptr.typed_ref::<BlockHash>()?;
    let operational_cert = operational_cert_rptr.typed_ref::<OperationalCert>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    let result = HeaderBody::new_headerbody(block_number, slot, Some(prev_hash), issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn info_action_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = InfoAction::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn int_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Int::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Int::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Int::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_new(x_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let x = x_rptr.typed_ref::<BigNum>()?;
    let result = Int::new(x);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_new_negative(x_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let x = x_rptr.typed_ref::<BigNum>()?;
    let result = Int::new_negative(x);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_new_i32(x_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let x  = x_long as i32;
    let result = Int::new_i32(x);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_is_positive(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.is_positive();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_as_positive(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.as_positive();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_as_negative(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.as_negative();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_as_i32(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.as_i32();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_as_i32_or_nothing(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.as_i32_or_nothing();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_as_i32_or_fail(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.as_i32_or_fail().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_to_str(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Int>()?;
    let result = self_ref.to_str();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn int_from_str(string_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let string: &str = string_str.into_str();
    let result = Int::from_str(string).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ipv4_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv4>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Ipv4::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv4>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Ipv4::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv4>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Ipv4::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_new(data_data: *const u8, data_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data = from_raw_parts(data_data, data_len).to_vec();
    let result = Ipv4::new(data).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv4_ip(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv4>()?;
    let result = self_ref.ip();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn ipv6_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv6>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Ipv6::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv6>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Ipv6::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv6>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Ipv6::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_new(data_data: *const u8, data_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data = from_raw_parts(data_data, data_len).to_vec();
    let result = Ipv6::new(data).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn ipv6_ip(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Ipv6>()?;
    let result = self_ref.ip();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn k_e_s_signature_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<KESSignature>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_signature_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = KESSignature::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = KESVKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<KESVKey>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<KESVKey>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = KESVKey::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<KESVKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn k_e_s_v_key_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = KESVKey::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn language_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Language>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Language::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Language>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Language::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Language>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Language::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_new_plutus_v1(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v1();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_new_plutus_v2(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v2();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_new_plutus_v3(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Language::new_plutus_v3();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn language_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Language>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn languages_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Languages::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn languages_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Languages>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn languages_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Languages>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn languages_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Languages>()?;
    let elem = elem_rptr.typed_ref::<Language>()?.clone();
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn languages_list(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Languages::list();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn legacy_daedalus_private_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = LegacyDaedalusPrivateKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn legacy_daedalus_private_key_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = self_ref.as_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn legacy_daedalus_private_key_chaincode(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<LegacyDaedalusPrivateKey>()?;
    let result = self_ref.chaincode();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn linear_fee_constant(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<LinearFee>()?;
    let result = self_ref.constant();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn linear_fee_coefficient(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<LinearFee>()?;
    let result = self_ref.coefficient();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn linear_fee_new(coefficient_rptr: RPtr, constant_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let coefficient = coefficient_rptr.typed_ref::<BigNum>()?;
    let constant = constant_rptr.typed_ref::<BigNum>()?;
    let result = LinearFee::new(coefficient, constant);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MIRToStakeCredentials::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MIRToStakeCredentials::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MIRToStakeCredentials::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MIRToStakeCredentials::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_insert(self_rptr: RPtr, cred_rptr: RPtr, delta_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred = cred_rptr.typed_ref::<Credential>()?;
    let delta = delta_rptr.typed_ref::<Int>()?;
    let result = self_ref.insert(cred, delta);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_get(self_rptr: RPtr, cred_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let cred = cred_rptr.typed_ref::<Credential>()?;
    let result = self_ref.get(cred);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn m_i_r_to_stake_credentials_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn malformed_address_original_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MalformedAddress>()?;
    let result = self_ref.original_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn malformed_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MalformedAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn malformed_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = MalformedAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn metadata_list_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataList>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MetadataList::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataList>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MetadataList::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MetadataList::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataList>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataList>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_list_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataList>()?;
    let elem = elem_rptr.typed_ref::<TransactionMetadatum>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn metadata_map_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MetadataMap::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MetadataMap::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MetadataMap::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key = key_rptr.typed_ref::<TransactionMetadatum>()?;
    let value = value_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_insert_str(self_rptr: RPtr, key_str: CharPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key: &str = key_str.into_str();
    let value = value_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.insert_str(key, value).into_result()?;
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_insert_i32(self_rptr: RPtr, key_long: i64, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key  = key_long as i32;
    let value = value_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.insert_i32(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key = key_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.get(key).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_get_str(self_rptr: RPtr, key_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key: &str = key_str.into_str();
    let result = self_ref.get_str(key).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_get_i32(self_rptr: RPtr, key_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key  = key_long as i32;
    let result = self_ref.get_i32(key).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_has(self_rptr: RPtr, key_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let key = key_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.has(key);
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn metadata_map_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MetadataMap>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn mint_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Mint::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Mint::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Mint::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Mint::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_new_from_entry(key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let key = key_rptr.typed_ref::<ScriptHash>()?;
    let value = value_rptr.typed_ref::<MintAssets>()?;
    let result = Mint::new_from_entry(key, value);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let key = key_rptr.typed_ref::<ScriptHash>()?;
    let value = value_rptr.typed_ref::<MintAssets>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let key = key_rptr.typed_ref::<ScriptHash>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_as_positive_multiasset(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.as_positive_multiasset();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_as_negative_multiasset(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Mint>()?;
    let result = self_ref.as_negative_multiasset();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn mint_assets_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MintAssets::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_assets_new_from_entry(key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let key = key_rptr.typed_ref::<AssetName>()?;
    let value = value_rptr.typed_ref::<Int>()?;
    let result = MintAssets::new_from_entry(key, value).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_assets_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintAssets>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_assets_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintAssets>()?;
    let key = key_rptr.typed_ref::<AssetName>()?;
    let value = value_rptr.typed_ref::<Int>()?.clone();
    let result = self_ref.insert(key, value).into_result()?;
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_assets_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintAssets>()?;
    let key = key_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_assets_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintAssets>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn mint_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MintBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_add_asset(self_rptr: RPtr, mint_rptr: RPtr, asset_name_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let mint = mint_rptr.typed_ref::<MintWitness>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let amount = amount_rptr.typed_ref::<Int>()?;
    self_ref.add_asset(mint, asset_name, amount).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_set_asset(self_rptr: RPtr, mint_rptr: RPtr, asset_name_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let mint = mint_rptr.typed_ref::<MintWitness>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let amount = amount_rptr.typed_ref::<Int>()?;
    self_ref.set_asset(mint, asset_name, amount).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.build();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_get_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.get_native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_get_plutus_witnesses(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.get_plutus_witnesses();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_get_redeemers(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.get_redeemers().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_has_plutus_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.has_plutus_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_builder_has_native_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintBuilder>()?;
    let result = self_ref.has_native_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn mint_witness_new_native_script(native_script_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let native_script = native_script_rptr.typed_ref::<NativeScript>()?;
    let result = MintWitness::new_native_script(native_script);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mint_witness_new_plutus_script(plutus_script_rptr: RPtr, redeemer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let plutus_script = plutus_script_rptr.typed_ref::<PlutusScriptSource>()?;
    let redeemer = redeemer_rptr.typed_ref::<Redeemer>()?;
    let result = MintWitness::new_plutus_script(plutus_script, redeemer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn mints_assets_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintsAssets>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mints_assets_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MintsAssets::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mints_assets_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MintsAssets::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mints_assets_add(self_rptr: RPtr, mint_assets_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintsAssets>()?;
    let mint_assets = mint_assets_rptr.typed_ref::<MintAssets>()?;
    self_ref.add(mint_assets);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn mints_assets_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintsAssets>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn mints_assets_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MintsAssets>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MoveInstantaneousReward::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MoveInstantaneousReward::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MoveInstantaneousReward::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_new_to_other_pot(pot_int: i32, amount_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pot = pot_int.to_enum()?;
    let amount = amount_rptr.typed_ref::<BigNum>()?;
    let result = MoveInstantaneousReward::new_to_other_pot(pot, amount);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_new_to_stake_creds(pot_int: i32, amounts_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pot = pot_int.to_enum()?;
    let amounts = amounts_rptr.typed_ref::<MIRToStakeCredentials>()?;
    let result = MoveInstantaneousReward::new_to_stake_creds(pot, amounts);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_pot(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.pot();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_as_to_other_pot(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.as_to_other_pot();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_reward_as_to_stake_creds(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = self_ref.as_to_stake_creds();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MoveInstantaneousRewardsCert::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MoveInstantaneousRewardsCert::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MoveInstantaneousRewardsCert::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_move_instantaneous_reward(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MoveInstantaneousRewardsCert>()?;
    let result = self_ref.move_instantaneous_reward();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn move_instantaneous_rewards_cert_new(move_instantaneous_reward_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let move_instantaneous_reward = move_instantaneous_reward_rptr.typed_ref::<MoveInstantaneousReward>()?;
    let result = MoveInstantaneousRewardsCert::new(move_instantaneous_reward);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn multi_asset_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MultiAsset::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MultiAsset::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MultiAsset::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = MultiAsset::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_insert(self_rptr: RPtr, policy_id_rptr: RPtr, assets_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let policy_id = policy_id_rptr.typed_ref::<ScriptHash>()?;
    let assets = assets_rptr.typed_ref::<Assets>()?;
    let result = self_ref.insert(policy_id, assets);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_get(self_rptr: RPtr, policy_id_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let policy_id = policy_id_rptr.typed_ref::<ScriptHash>()?;
    let result = self_ref.get(policy_id);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_set_asset(self_rptr: RPtr, policy_id_rptr: RPtr, asset_name_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let policy_id = policy_id_rptr.typed_ref::<ScriptHash>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let value = value_rptr.typed_ref::<BigNum>()?.clone();
    let result = self_ref.set_asset(policy_id, asset_name, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_get_asset(self_rptr: RPtr, policy_id_rptr: RPtr, asset_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let policy_id = policy_id_rptr.typed_ref::<ScriptHash>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let result = self_ref.get_asset(policy_id, asset_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_asset_sub(self_rptr: RPtr, rhs_ma_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiAsset>()?;
    let rhs_ma = rhs_ma_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.sub(rhs_ma);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn multi_host_name_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiHostName>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = MultiHostName::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiHostName>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = MultiHostName::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiHostName>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = MultiHostName::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_dns_name(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<MultiHostName>()?;
    let result = self_ref.dns_name();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn multi_host_name_new(dns_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let dns_name = dns_name_rptr.typed_ref::<DNSRecordSRV>()?;
    let result = MultiHostName::new(dns_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn native_script_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = NativeScript::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = NativeScript::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = NativeScript::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_script_pubkey(script_pubkey_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_pubkey = script_pubkey_rptr.typed_ref::<ScriptPubkey>()?;
    let result = NativeScript::new_script_pubkey(script_pubkey);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_script_all(script_all_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_all = script_all_rptr.typed_ref::<ScriptAll>()?;
    let result = NativeScript::new_script_all(script_all);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_script_any(script_any_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_any = script_any_rptr.typed_ref::<ScriptAny>()?;
    let result = NativeScript::new_script_any(script_any);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_script_n_of_k(script_n_of_k_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_n_of_k = script_n_of_k_rptr.typed_ref::<ScriptNOfK>()?;
    let result = NativeScript::new_script_n_of_k(script_n_of_k);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_timelock_start(timelock_start_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let timelock_start = timelock_start_rptr.typed_ref::<TimelockStart>()?;
    let result = NativeScript::new_timelock_start(timelock_start);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_new_timelock_expiry(timelock_expiry_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let timelock_expiry = timelock_expiry_rptr.typed_ref::<TimelockExpiry>()?;
    let result = NativeScript::new_timelock_expiry(timelock_expiry);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_script_pubkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_script_pubkey();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_script_all(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_script_all();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_script_any(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_script_any();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_script_n_of_k(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_script_n_of_k();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_timelock_start(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_timelock_start();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_as_timelock_expiry(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.as_timelock_expiry();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_get_required_signers(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScript>()?;
    let result = self_ref.get_required_signers();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn native_script_source_new(script_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<NativeScript>()?;
    let result = NativeScriptSource::new(script);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_script_source_new_ref_input(script_hash_rptr: RPtr, input_rptr: RPtr, required_signers_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_hash = script_hash_rptr.typed_ref::<ScriptHash>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let required_signers = required_signers_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let result = NativeScriptSource::new_ref_input(script_hash, input, required_signers);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn native_scripts_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NativeScripts::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let elem = elem_rptr.typed_ref::<NativeScript>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = NativeScripts::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = NativeScripts::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NativeScripts>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn native_scripts_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = NativeScripts::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn network_id_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkId>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = NetworkId::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkId>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = NetworkId::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkId>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = NetworkId::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_testnet(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NetworkId::testnet();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_mainnet(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NetworkId::mainnet();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_id_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkId>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn network_info_new(network_id_long: i64, protocol_magic_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let network_id  = network_id_long as u8;
    let protocol_magic  = protocol_magic_long as u32;
    let result = NetworkInfo::new(network_id, protocol_magic);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_info_network_id(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkInfo>()?;
    let result = self_ref.network_id();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_info_protocol_magic(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NetworkInfo>()?;
    let result = self_ref.protocol_magic();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_info_testnet_preview(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preview();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_info_testnet_preprod(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NetworkInfo::testnet_preprod();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn network_info_mainnet(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NetworkInfo::mainnet();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = NewConstitutionAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = NewConstitutionAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = NewConstitutionAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_gov_action_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.gov_action_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_constitution(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.constitution();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_new(constitution_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let constitution = constitution_rptr.typed_ref::<Constitution>()?;
    let result = NewConstitutionAction::new(constitution);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_new_with_action_id(gov_action_id_rptr: RPtr, constitution_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let constitution = constitution_rptr.typed_ref::<Constitution>()?;
    let result = NewConstitutionAction::new_with_action_id(gov_action_id, constitution);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn new_constitution_action_has_script_hash(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NewConstitutionAction>()?;
    let result = self_ref.has_script_hash();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = NoConfidenceAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = NoConfidenceAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = NoConfidenceAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_gov_action_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<NoConfidenceAction>()?;
    let result = self_ref.gov_action_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = NoConfidenceAction::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn no_confidence_action_new_with_action_id(gov_action_id_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let result = NoConfidenceAction::new_with_action_id(gov_action_id);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn nonce_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Nonce>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Nonce::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Nonce>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Nonce::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Nonce>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Nonce::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_new_identity(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Nonce::new_identity();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_new_from_hash(hash_data: *const u8, hash_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hash = from_raw_parts(hash_data, hash_len).to_vec();
    let result = Nonce::new_from_hash(hash).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn nonce_get_hash(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Nonce>()?;
    let result = self_ref.get_hash();
    Ok::<Option<DataPtr>, String>(result.into_option())
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn operational_cert_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = OperationalCert::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = OperationalCert::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = OperationalCert::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_hot_vkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.hot_vkey();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_sequence_number(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.sequence_number();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_kes_period(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.kes_period();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_sigma(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OperationalCert>()?;
    let result = self_ref.sigma();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn operational_cert_new(hot_vkey_rptr: RPtr, sequence_number_long: i64, kes_period_long: i64, sigma_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hot_vkey = hot_vkey_rptr.typed_ref::<KESVKey>()?;
    let sequence_number  = sequence_number_long as u32;
    let kes_period  = kes_period_long as u32;
    let sigma = sigma_rptr.typed_ref::<Ed25519Signature>()?;
    let result = OperationalCert::new(hot_vkey, sequence_number, kes_period, sigma);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn output_datum_new_data_hash(data_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data_hash = data_hash_rptr.typed_ref::<DataHash>()?;
    let result = OutputDatum::new_data_hash(data_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn output_datum_new_data(data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let data = data_rptr.typed_ref::<PlutusData>()?;
    let result = OutputDatum::new_data(data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn output_datum_data_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OutputDatum>()?;
    let result = self_ref.data_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn output_datum_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<OutputDatum>()?;
    let result = self_ref.data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ParameterChangeAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ParameterChangeAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ParameterChangeAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_gov_action_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.gov_action_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_protocol_param_updates(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.protocol_param_updates();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_policy_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ParameterChangeAction>()?;
    let result = self_ref.policy_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_new(protocol_param_updates_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let protocol_param_updates = protocol_param_updates_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = ParameterChangeAction::new(protocol_param_updates);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_new_with_action_id(gov_action_id_rptr: RPtr, protocol_param_updates_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let protocol_param_updates = protocol_param_updates_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = ParameterChangeAction::new_with_action_id(gov_action_id, protocol_param_updates);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_new_with_policy_hash(protocol_param_updates_rptr: RPtr, policy_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let protocol_param_updates = protocol_param_updates_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let policy_hash = policy_hash_rptr.typed_ref::<ScriptHash>()?;
    let result = ParameterChangeAction::new_with_policy_hash(protocol_param_updates, policy_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn parameter_change_action_new_with_policy_hash_and_action_id(gov_action_id_rptr: RPtr, protocol_param_updates_rptr: RPtr, policy_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let protocol_param_updates = protocol_param_updates_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let policy_hash = policy_hash_rptr.typed_ref::<ScriptHash>()?;
    let result = ParameterChangeAction::new_with_policy_hash_and_action_id(gov_action_id, protocol_param_updates, policy_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_data_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusData::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PlutusData::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_constr_plutus_data(constr_plutus_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let constr_plutus_data = constr_plutus_data_rptr.typed_ref::<ConstrPlutusData>()?;
    let result = PlutusData::new_constr_plutus_data(constr_plutus_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_empty_constr_plutus_data(alternative_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let alternative = alternative_rptr.typed_ref::<BigNum>()?;
    let result = PlutusData::new_empty_constr_plutus_data(alternative);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_single_value_constr_plutus_data(alternative_rptr: RPtr, plutus_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let alternative = alternative_rptr.typed_ref::<BigNum>()?;
    let plutus_data = plutus_data_rptr.typed_ref::<PlutusData>()?;
    let result = PlutusData::new_single_value_constr_plutus_data(alternative, plutus_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_map(map_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let map = map_rptr.typed_ref::<PlutusMap>()?;
    let result = PlutusData::new_map(map);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_list(list_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let list = list_rptr.typed_ref::<PlutusList>()?;
    let result = PlutusData::new_list(list);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_integer(integer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let integer = integer_rptr.typed_ref::<BigInt>()?;
    let result = PlutusData::new_integer(integer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_new_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusData::new_bytes(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_as_constr_plutus_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.as_constr_plutus_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_as_map(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.as_map();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_as_list(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.as_list();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_as_integer(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.as_integer();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.as_bytes();
    Ok::<Option<DataPtr>, String>(result.into_option())
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_to_json(self_rptr: RPtr, schema_int: i32, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusData>()?;
    let schema = schema_int.to_enum()?;
    let result = self_ref.to_json(schema).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_from_json(json_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = PlutusData::from_json(json, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_data_from_address(address_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let address = address_rptr.typed_ref::<Address>()?;
    let result = PlutusData::from_address(address).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_list_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusList>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusList::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusList>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PlutusList::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PlutusList::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusList>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusList>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_list_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusList>()?;
    let elem = elem_rptr.typed_ref::<PlutusData>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_map_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusMap::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PlutusMap::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PlutusMap::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let key = key_rptr.typed_ref::<PlutusData>()?;
    let value = value_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let key = key_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_map_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusMap>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_script_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScript>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScript>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PlutusScript::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_new(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::new(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_new_v2(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::new_v2(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_new_v3(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::new_v3(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_new_with_version(bytes_data: *const u8, bytes_len: usize, language_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let language = language_rptr.typed_ref::<Language>()?;
    let result = PlutusScript::new_with_version(bytes, language);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScript>()?;
    let result = self_ref.bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_bytes_v2(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::from_bytes_v2(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_bytes_v3(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScript::from_bytes_v3(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_bytes_with_version(bytes_data: *const u8, bytes_len: usize, language_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let language = language_rptr.typed_ref::<Language>()?;
    let result = PlutusScript::from_bytes_with_version(bytes, language).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_from_hex_with_version(hex_str_str: CharPtr, language_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let language = language_rptr.typed_ref::<Language>()?;
    let result = PlutusScript::from_hex_with_version(hex_str, language).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScript>()?;
    let result = self_ref.hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_language_version(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScript>()?;
    let result = self_ref.language_version();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_script_source_new(script_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<PlutusScript>()?;
    let result = PlutusScriptSource::new(script);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_script_source_new_ref_input(script_hash_rptr: RPtr, input_rptr: RPtr, lang_ver_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script_hash = script_hash_rptr.typed_ref::<ScriptHash>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let lang_ver = lang_ver_rptr.typed_ref::<Language>()?;
    let result = PlutusScriptSource::new_ref_input(script_hash, input, lang_ver);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PlutusScripts::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PlutusScripts::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PlutusScripts::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PlutusScripts::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_scripts_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusScripts>()?;
    let elem = elem_rptr.typed_ref::<PlutusScript>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_witness_new(script_rptr: RPtr, datum_rptr: RPtr, redeemer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<PlutusScript>()?;
    let datum = datum_rptr.typed_ref::<PlutusData>()?;
    let redeemer = redeemer_rptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new(script, datum, redeemer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_new_with_ref(script_rptr: RPtr, datum_rptr: RPtr, redeemer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<PlutusScriptSource>()?;
    let datum = datum_rptr.typed_ref::<DatumSource>()?;
    let redeemer = redeemer_rptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_with_ref(script, datum, redeemer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_new_without_datum(script_rptr: RPtr, redeemer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<PlutusScript>()?;
    let redeemer = redeemer_rptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_without_datum(script, redeemer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_new_with_ref_without_datum(script_rptr: RPtr, redeemer_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let script = script_rptr.typed_ref::<PlutusScriptSource>()?;
    let redeemer = redeemer_rptr.typed_ref::<Redeemer>()?;
    let result = PlutusWitness::new_with_ref_without_datum(script, redeemer);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_script(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitness>()?;
    let result = self_ref.script();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_datum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitness>()?;
    let result = self_ref.datum();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witness_redeemer(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitness>()?;
    let result = self_ref.redeemer();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn plutus_witnesses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PlutusWitnesses::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witnesses_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitnesses>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witnesses_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitnesses>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn plutus_witnesses_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PlutusWitnesses>()?;
    let elem = elem_rptr.typed_ref::<PlutusWitness>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn pointer_new(slot_long: i64, tx_index_long: i64, cert_index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot  = slot_long as u32;
    let tx_index  = tx_index_long as u32;
    let cert_index  = cert_index_long as u32;
    let result = Pointer::new(slot, tx_index, cert_index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_new_pointer(slot_rptr: RPtr, tx_index_rptr: RPtr, cert_index_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot = slot_rptr.typed_ref::<BigNum>()?;
    let tx_index = tx_index_rptr.typed_ref::<BigNum>()?;
    let cert_index = cert_index_rptr.typed_ref::<BigNum>()?;
    let result = Pointer::new_pointer(slot, tx_index, cert_index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_slot(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.slot().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_tx_index(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.tx_index().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_cert_index(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.cert_index().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_slot_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.slot_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_tx_index_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.tx_index_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_cert_index_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Pointer>()?;
    let result = self_ref.cert_index_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pointer_address_new(network_long: i64, payment_rptr: RPtr, stake_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let network  = network_long as u8;
    let payment = payment_rptr.typed_ref::<Credential>()?;
    let stake = stake_rptr.typed_ref::<Pointer>()?;
    let result = PointerAddress::new(network, payment, stake);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_address_payment_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PointerAddress>()?;
    let result = self_ref.payment_cred();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_address_stake_pointer(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PointerAddress>()?;
    let result = self_ref.stake_pointer();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PointerAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pointer_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = PointerAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pool_metadata_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadata>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolMetadata::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadata>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PoolMetadata::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadata>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PoolMetadata::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_url(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadata>()?;
    let result = self_ref.url();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_pool_metadata_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadata>()?;
    let result = self_ref.pool_metadata_hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_new(url_rptr: RPtr, pool_metadata_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let url = url_rptr.typed_ref::<URL>()?;
    let pool_metadata_hash = pool_metadata_hash_rptr.typed_ref::<PoolMetadataHash>()?;
    let result = PoolMetadata::new(url, pool_metadata_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolMetadataHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadataHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadataHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = PoolMetadataHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolMetadataHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_metadata_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = PoolMetadataHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pool_params_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolParams::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PoolParams::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PoolParams::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_operator(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.operator();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_vrf_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.vrf_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_pledge(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.pledge();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_cost(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.cost();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_margin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.margin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_reward_account(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.reward_account();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_pool_owners(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.pool_owners();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_relays(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.relays();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_pool_metadata(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolParams>()?;
    let result = self_ref.pool_metadata();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_new(operator_rptr: RPtr, vrf_keyhash_rptr: RPtr, pledge_rptr: RPtr, cost_rptr: RPtr, margin_rptr: RPtr, reward_account_rptr: RPtr, pool_owners_rptr: RPtr, relays_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let operator = operator_rptr.typed_ref::<Ed25519KeyHash>()?;
    let vrf_keyhash = vrf_keyhash_rptr.typed_ref::<VRFKeyHash>()?;
    let pledge = pledge_rptr.typed_ref::<BigNum>()?;
    let cost = cost_rptr.typed_ref::<BigNum>()?;
    let margin = margin_rptr.typed_ref::<UnitInterval>()?;
    let reward_account = reward_account_rptr.typed_ref::<RewardAddress>()?;
    let pool_owners = pool_owners_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let relays = relays_rptr.typed_ref::<Relays>()?;
    let result = PoolParams::new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_params_new_with_pool_metadata(operator_rptr: RPtr, vrf_keyhash_rptr: RPtr, pledge_rptr: RPtr, cost_rptr: RPtr, margin_rptr: RPtr, reward_account_rptr: RPtr, pool_owners_rptr: RPtr, relays_rptr: RPtr, pool_metadata_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let operator = operator_rptr.typed_ref::<Ed25519KeyHash>()?;
    let vrf_keyhash = vrf_keyhash_rptr.typed_ref::<VRFKeyHash>()?;
    let pledge = pledge_rptr.typed_ref::<BigNum>()?;
    let cost = cost_rptr.typed_ref::<BigNum>()?;
    let margin = margin_rptr.typed_ref::<UnitInterval>()?;
    let reward_account = reward_account_rptr.typed_ref::<RewardAddress>()?;
    let pool_owners = pool_owners_rptr.typed_ref::<Ed25519KeyHashes>()?;
    let relays = relays_rptr.typed_ref::<Relays>()?;
    let pool_metadata = pool_metadata_rptr.typed_ref::<PoolMetadata>()?.clone();
    let result = PoolParams::new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, Some(pool_metadata));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn pool_registration_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRegistration>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolRegistration::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRegistration>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PoolRegistration::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRegistration>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PoolRegistration::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_pool_params(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRegistration>()?;
    let result = self_ref.pool_params();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_registration_new(pool_params_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pool_params = pool_params_rptr.typed_ref::<PoolParams>()?;
    let result = PoolRegistration::new(pool_params);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pool_retirement_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRetirement>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolRetirement::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRetirement>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PoolRetirement::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRetirement>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PoolRetirement::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_pool_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRetirement>()?;
    let result = self_ref.pool_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_epoch(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolRetirement>()?;
    let result = self_ref.epoch();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_retirement_new(pool_keyhash_rptr: RPtr, epoch_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pool_keyhash = pool_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let epoch  = epoch_long as u32;
    let result = PoolRetirement::new(pool_keyhash, epoch);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = PoolVotingThresholds::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PoolVotingThresholds::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = PoolVotingThresholds::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_new(motion_no_confidence_rptr: RPtr, committee_normal_rptr: RPtr, committee_no_confidence_rptr: RPtr, hard_fork_initiation_rptr: RPtr, security_relevant_threshold_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let motion_no_confidence = motion_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    let committee_normal = committee_normal_rptr.typed_ref::<UnitInterval>()?;
    let committee_no_confidence = committee_no_confidence_rptr.typed_ref::<UnitInterval>()?;
    let hard_fork_initiation = hard_fork_initiation_rptr.typed_ref::<UnitInterval>()?;
    let security_relevant_threshold = security_relevant_threshold_rptr.typed_ref::<UnitInterval>()?;
    let result = PoolVotingThresholds::new(motion_no_confidence, committee_normal, committee_no_confidence, hard_fork_initiation, security_relevant_threshold);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_motion_no_confidence(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.motion_no_confidence();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_committee_normal(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.committee_normal();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_committee_no_confidence(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.committee_no_confidence();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn pool_voting_thresholds_hard_fork_initiation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PoolVotingThresholds>()?;
    let result = self_ref.hard_fork_initiation();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn private_key_to_public(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PrivateKey>()?;
    let result = self_ref.to_public();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_generate_ed25519(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_generate_ed25519extended(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PrivateKey::generate_ed25519extended().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_from_bech32(bech32_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech32_str: &str = bech32_str_str.into_str();
    let result = PrivateKey::from_bech32(bech32_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PrivateKey>()?;
    let result = self_ref.to_bech32();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PrivateKey>()?;
    let result = self_ref.as_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_from_extended_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = PrivateKey::from_extended_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_from_normal_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = PrivateKey::from_normal_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_sign(self_rptr: RPtr, message_data: *const u8, message_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PrivateKey>()?;
    let message = from_raw_parts(message_data, message_len);
    let result = self_ref.sign(message);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PrivateKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn private_key_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PrivateKey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ProposedProtocolParameterUpdates::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ProposedProtocolParameterUpdates::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ProposedProtocolParameterUpdates::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = ProposedProtocolParameterUpdates::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let key = key_rptr.typed_ref::<GenesisHash>()?;
    let value = value_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let key = key_rptr.typed_ref::<GenesisHash>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn proposed_protocol_parameter_updates_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ProtocolParamUpdate::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ProtocolParamUpdate::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ProtocolParamUpdate::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_minfee_a(self_rptr: RPtr, minfee_a_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let minfee_a = minfee_a_rptr.typed_ref::<BigNum>()?;
    self_ref.set_minfee_a(minfee_a);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_minfee_a(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.minfee_a();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_minfee_b(self_rptr: RPtr, minfee_b_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let minfee_b = minfee_b_rptr.typed_ref::<BigNum>()?;
    self_ref.set_minfee_b(minfee_b);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_minfee_b(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.minfee_b();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_block_body_size(self_rptr: RPtr, max_block_body_size_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_body_size  = max_block_body_size_long as u32;
    self_ref.set_max_block_body_size(max_block_body_size);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_block_body_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_block_body_size();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_tx_size(self_rptr: RPtr, max_tx_size_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_tx_size  = max_tx_size_long as u32;
    self_ref.set_max_tx_size(max_tx_size);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_tx_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_tx_size();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_block_header_size(self_rptr: RPtr, max_block_header_size_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_header_size  = max_block_header_size_long as u32;
    self_ref.set_max_block_header_size(max_block_header_size);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_block_header_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_block_header_size();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_key_deposit(self_rptr: RPtr, key_deposit_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    self_ref.set_key_deposit(key_deposit);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_key_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.key_deposit();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_pool_deposit(self_rptr: RPtr, pool_deposit_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    self_ref.set_pool_deposit(pool_deposit);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_pool_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.pool_deposit();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_epoch(self_rptr: RPtr, max_epoch_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_epoch  = max_epoch_long as u32;
    self_ref.set_max_epoch(max_epoch);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_epoch(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_epoch();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_n_opt(self_rptr: RPtr, n_opt_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let n_opt  = n_opt_long as u32;
    self_ref.set_n_opt(n_opt);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_n_opt(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.n_opt();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_pool_pledge_influence(self_rptr: RPtr, pool_pledge_influence_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_pledge_influence = pool_pledge_influence_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_pool_pledge_influence(pool_pledge_influence);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_pool_pledge_influence(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.pool_pledge_influence();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_expansion_rate(self_rptr: RPtr, expansion_rate_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let expansion_rate = expansion_rate_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_expansion_rate(expansion_rate);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_expansion_rate(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.expansion_rate();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_treasury_growth_rate(self_rptr: RPtr, treasury_growth_rate_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let treasury_growth_rate = treasury_growth_rate_rptr.typed_ref::<UnitInterval>()?;
    self_ref.set_treasury_growth_rate(treasury_growth_rate);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_treasury_growth_rate(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.treasury_growth_rate();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_d(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.d();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_extra_entropy(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.extra_entropy();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_protocol_version(self_rptr: RPtr, protocol_version_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let protocol_version = protocol_version_rptr.typed_ref::<ProtocolVersion>()?;
    self_ref.set_protocol_version(protocol_version);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_protocol_version(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.protocol_version();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_min_pool_cost(self_rptr: RPtr, min_pool_cost_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let min_pool_cost = min_pool_cost_rptr.typed_ref::<BigNum>()?;
    self_ref.set_min_pool_cost(min_pool_cost);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_min_pool_cost(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.min_pool_cost();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_ada_per_utxo_byte(self_rptr: RPtr, ada_per_utxo_byte_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let ada_per_utxo_byte = ada_per_utxo_byte_rptr.typed_ref::<BigNum>()?;
    self_ref.set_ada_per_utxo_byte(ada_per_utxo_byte);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_ada_per_utxo_byte(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.ada_per_utxo_byte();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_cost_models(self_rptr: RPtr, cost_models_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let cost_models = cost_models_rptr.typed_ref::<Costmdls>()?;
    self_ref.set_cost_models(cost_models);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_cost_models(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.cost_models();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_execution_costs(self_rptr: RPtr, execution_costs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let execution_costs = execution_costs_rptr.typed_ref::<ExUnitPrices>()?;
    self_ref.set_execution_costs(execution_costs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_execution_costs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.execution_costs();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_tx_ex_units(self_rptr: RPtr, max_tx_ex_units_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_tx_ex_units = max_tx_ex_units_rptr.typed_ref::<ExUnits>()?;
    self_ref.set_max_tx_ex_units(max_tx_ex_units);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_tx_ex_units(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_tx_ex_units();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_block_ex_units(self_rptr: RPtr, max_block_ex_units_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_block_ex_units = max_block_ex_units_rptr.typed_ref::<ExUnits>()?;
    self_ref.set_max_block_ex_units(max_block_ex_units);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_block_ex_units(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_block_ex_units();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_value_size(self_rptr: RPtr, max_value_size_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_value_size  = max_value_size_long as u32;
    self_ref.set_max_value_size(max_value_size);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_value_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_value_size();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_collateral_percentage(self_rptr: RPtr, collateral_percentage_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let collateral_percentage  = collateral_percentage_long as u32;
    self_ref.set_collateral_percentage(collateral_percentage);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_collateral_percentage(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.collateral_percentage();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_max_collateral_inputs(self_rptr: RPtr, max_collateral_inputs_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let max_collateral_inputs  = max_collateral_inputs_long as u32;
    self_ref.set_max_collateral_inputs(max_collateral_inputs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_max_collateral_inputs(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.max_collateral_inputs();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_pool_voting_thresholds(self_rptr: RPtr, pool_voting_thresholds_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let pool_voting_thresholds = pool_voting_thresholds_rptr.typed_ref::<PoolVotingThresholds>()?;
    self_ref.set_pool_voting_thresholds(pool_voting_thresholds);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_pool_voting_thresholds(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.pool_voting_thresholds();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_drep_voting_thresholds(self_rptr: RPtr, drep_voting_thresholds_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_voting_thresholds = drep_voting_thresholds_rptr.typed_ref::<DrepVotingThresholds>()?;
    self_ref.set_drep_voting_thresholds(drep_voting_thresholds);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_drep_voting_thresholds(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.drep_voting_thresholds();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_min_committee_size(self_rptr: RPtr, min_committee_size_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let min_committee_size  = min_committee_size_long as u32;
    self_ref.set_min_committee_size(min_committee_size);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_min_committee_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.min_committee_size();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_committee_term_limit(self_rptr: RPtr, committee_term_limit_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let committee_term_limit  = committee_term_limit_long as u32;
    self_ref.set_committee_term_limit(committee_term_limit);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_committee_term_limit(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.committee_term_limit();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_governance_action_validity_period(self_rptr: RPtr, governance_action_validity_period_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let governance_action_validity_period  = governance_action_validity_period_long as u32;
    self_ref.set_governance_action_validity_period(governance_action_validity_period);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_governance_action_validity_period(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.governance_action_validity_period();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_governance_action_deposit(self_rptr: RPtr, governance_action_deposit_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let governance_action_deposit = governance_action_deposit_rptr.typed_ref::<BigNum>()?;
    self_ref.set_governance_action_deposit(governance_action_deposit);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_governance_action_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.governance_action_deposit();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_drep_deposit(self_rptr: RPtr, drep_deposit_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_deposit = drep_deposit_rptr.typed_ref::<BigNum>()?;
    self_ref.set_drep_deposit(drep_deposit);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_drep_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.drep_deposit();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_set_drep_inactivity_period(self_rptr: RPtr, drep_inactivity_period_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let drep_inactivity_period  = drep_inactivity_period_long as u32;
    self_ref.set_drep_inactivity_period(drep_inactivity_period);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_drep_inactivity_period(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolParamUpdate>()?;
    let result = self_ref.drep_inactivity_period();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_param_update_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = ProtocolParamUpdate::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn protocol_version_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolVersion>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ProtocolVersion::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolVersion>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ProtocolVersion::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolVersion>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ProtocolVersion::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_major(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolVersion>()?;
    let result = self_ref.major();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_minor(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ProtocolVersion>()?;
    let result = self_ref.minor();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn protocol_version_new(major_long: i64, minor_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let major  = major_long as u32;
    let minor  = minor_long as u32;
    let result = ProtocolVersion::new(major, minor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn public_key_from_bech32(bech32_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech32_str: &str = bech32_str_str.into_str();
    let result = PublicKey::from_bech32(bech32_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_to_bech32(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKey>()?;
    let result = self_ref.to_bech32();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKey>()?;
    let result = self_ref.as_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = PublicKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_verify(self_rptr: RPtr, data_data: *const u8, data_len: usize, signature_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKey>()?;
    let data = from_raw_parts(data_data, data_len);
    let signature = signature_rptr.typed_ref::<Ed25519Signature>()?;
    let result = self_ref.verify(data, signature);
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKey>()?;
    let result = self_ref.hash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_key_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = PublicKey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn public_keys_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = PublicKeys::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_keys_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKeys>()?;
    let result = self_ref.size();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_keys_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKeys>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn public_keys_add(self_rptr: RPtr, key_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<PublicKeys>()?;
    let key = key_rptr.typed_ref::<PublicKey>()?;
    self_ref.add(key);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn redeemer_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Redeemer::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Redeemer::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Redeemer::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.tag();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_index(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.index();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.data();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_ex_units(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemer>()?;
    let result = self_ref.ex_units();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_new(tag_rptr: RPtr, index_rptr: RPtr, data_rptr: RPtr, ex_units_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tag = tag_rptr.typed_ref::<RedeemerTag>()?;
    let index = index_rptr.typed_ref::<BigNum>()?;
    let data = data_rptr.typed_ref::<PlutusData>()?;
    let ex_units = ex_units_rptr.typed_ref::<ExUnits>()?;
    let result = Redeemer::new(tag, index, data, ex_units);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RedeemerTag>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = RedeemerTag::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RedeemerTag>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = RedeemerTag::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RedeemerTag>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = RedeemerTag::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_spend(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_spend();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_mint(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_mint();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_cert(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_cert();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_reward(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_reward();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_vote(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_vote();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_new_voting_proposal(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RedeemerTag::new_voting_proposal();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemer_tag_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RedeemerTag>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn redeemers_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Redeemers::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Redeemers::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Redeemers::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Redeemers::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_new_with_serialization_format(redeemers_rptr: RPtr, serialization_format_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let redeemers = redeemers_rptr.typed_ref::<Redeemer>()?.clone();
    let serialization_format = serialization_format_int.to_enum()?;
    let result = Redeemers::new_with_serialization_format(redeemers, serialization_format);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let elem = elem_rptr.typed_ref::<Redeemer>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn redeemers_total_ex_units(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Redeemers>()?;
    let result = self_ref.total_ex_units().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn relay_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Relay::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Relay::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Relay::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_new_single_host_addr(single_host_addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let single_host_addr = single_host_addr_rptr.typed_ref::<SingleHostAddr>()?;
    let result = Relay::new_single_host_addr(single_host_addr);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_new_single_host_name(single_host_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let single_host_name = single_host_name_rptr.typed_ref::<SingleHostName>()?;
    let result = Relay::new_single_host_name(single_host_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_new_multi_host_name(multi_host_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let multi_host_name = multi_host_name_rptr.typed_ref::<MultiHostName>()?;
    let result = Relay::new_multi_host_name(multi_host_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_as_single_host_addr(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.as_single_host_addr();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_as_single_host_name(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.as_single_host_name();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relay_as_multi_host_name(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relay>()?;
    let result = self_ref.as_multi_host_name();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn relays_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Relays::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Relays::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Relays::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Relays::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn relays_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Relays>()?;
    let elem = elem_rptr.typed_ref::<Relay>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn reward_address_new(network_long: i64, payment_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let network  = network_long as u8;
    let payment = payment_rptr.typed_ref::<Credential>()?;
    let result = RewardAddress::new(network, payment);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_address_payment_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddress>()?;
    let result = self_ref.payment_cred();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_address_to_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddress>()?;
    let result = self_ref.to_address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_address_from_address(addr_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr = addr_rptr.typed_ref::<Address>()?;
    let result = RewardAddress::from_address(addr);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn reward_addresses_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = RewardAddresses::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = RewardAddresses::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = RewardAddresses::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = RewardAddresses::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn reward_addresses_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<RewardAddresses>()?;
    let elem = elem_rptr.typed_ref::<RewardAddress>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_all_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAll>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptAll::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAll>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptAll::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAll>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptAll::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAll>()?;
    let result = self_ref.native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_all_new(native_scripts_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let native_scripts = native_scripts_rptr.typed_ref::<NativeScripts>()?;
    let result = ScriptAll::new(native_scripts);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_any_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAny>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptAny::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAny>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptAny::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAny>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptAny::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptAny>()?;
    let result = self_ref.native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_any_new(native_scripts_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let native_scripts = native_scripts_rptr.typed_ref::<NativeScripts>()?;
    let result = ScriptAny::new(native_scripts);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_data_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptDataHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_data_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptDataHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_data_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptDataHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_data_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = ScriptDataHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_data_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptDataHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_data_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = ScriptDataHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = ScriptHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = ScriptHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_hashes_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptHashes::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptHashes::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptHashes::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = ScriptHashes::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_hashes_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptHashes>()?;
    let elem = elem_rptr.typed_ref::<ScriptHash>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptNOfK>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptNOfK::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptNOfK>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptNOfK::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptNOfK>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptNOfK::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_n(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptNOfK>()?;
    let result = self_ref.n();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptNOfK>()?;
    let result = self_ref.native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_n_of_k_new(n_long: i64, native_scripts_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let n  = n_long as u32;
    let native_scripts = native_scripts_rptr.typed_ref::<NativeScripts>()?;
    let result = ScriptNOfK::new(n, native_scripts);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_pubkey_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptPubkey>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptPubkey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptPubkey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptPubkey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptPubkey>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptPubkey::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_addr_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptPubkey>()?;
    let result = self_ref.addr_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_pubkey_new(addr_keyhash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let addr_keyhash = addr_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = ScriptPubkey::new(addr_keyhash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn script_ref_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = ScriptRef::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = ScriptRef::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = ScriptRef::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_new_native_script(native_script_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let native_script = native_script_rptr.typed_ref::<NativeScript>()?;
    let result = ScriptRef::new_native_script(native_script);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_new_plutus_script(plutus_script_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let plutus_script = plutus_script_rptr.typed_ref::<PlutusScript>()?;
    let result = ScriptRef::new_plutus_script(plutus_script);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_is_native_script(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.is_native_script();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_is_plutus_script(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.is_plutus_script();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_native_script(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.native_script();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn script_ref_plutus_script(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.plutus_script();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn single_host_addr_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = SingleHostAddr::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = SingleHostAddr::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = SingleHostAddr::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_port(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.port();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_ipv4(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.ipv4();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_ipv6(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostAddr>()?;
    let result = self_ref.ipv6();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = SingleHostAddr::new(None, None, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_port(port_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let port  = port_long as u16;
    let result = SingleHostAddr::new(Some(port), None, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_ipv4(ipv4_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let ipv4 = ipv4_rptr.typed_ref::<Ipv4>()?.clone();
    let result = SingleHostAddr::new(None, Some(ipv4), None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_port_ipv4(port_long: i64, ipv4_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let port  = port_long as u16;
    let ipv4 = ipv4_rptr.typed_ref::<Ipv4>()?.clone();
    let result = SingleHostAddr::new(Some(port), Some(ipv4), None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_ipv6(ipv6_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let ipv6 = ipv6_rptr.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(None, None, Some(ipv6));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_port_ipv6(port_long: i64, ipv6_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let port  = port_long as u16;
    let ipv6 = ipv6_rptr.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(Some(port), None, Some(ipv6));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_ipv4_ipv6(ipv4_rptr: RPtr, ipv6_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let ipv4 = ipv4_rptr.typed_ref::<Ipv4>()?.clone();
    let ipv6 = ipv6_rptr.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(None, Some(ipv4), Some(ipv6));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_addr_new_with_port_ipv4_ipv6(port_long: i64, ipv4_rptr: RPtr, ipv6_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let port  = port_long as u16;
    let ipv4 = ipv4_rptr.typed_ref::<Ipv4>()?.clone();
    let ipv6 = ipv6_rptr.typed_ref::<Ipv6>()?.clone();
    let result = SingleHostAddr::new(Some(port), Some(ipv4), Some(ipv6));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn single_host_name_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostName>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = SingleHostName::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostName>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = SingleHostName::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostName>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = SingleHostName::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_port(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostName>()?;
    let result = self_ref.port();
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_dns_name(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<SingleHostName>()?;
    let result = self_ref.dns_name();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_new(dns_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let dns_name = dns_name_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = SingleHostName::new(None, dns_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn single_host_name_new_with_port(port_long: i64, dns_name_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let port  = port_long as u16;
    let dns_name = dns_name_rptr.typed_ref::<DNSRecordAorAAAA>()?;
    let result = SingleHostName::new(Some(port), dns_name);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeAndVoteDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeAndVoteDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeAndVoteDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_pool_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.pool_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_drep(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.drep();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_new(stake_credential_rptr: RPtr, pool_keyhash_rptr: RPtr, drep_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let pool_keyhash = pool_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let drep = drep_rptr.typed_ref::<DRep>()?;
    let result = StakeAndVoteDelegation::new(stake_credential, pool_keyhash, drep);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_and_vote_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeAndVoteDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn stake_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_pool_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.pool_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_new(stake_credential_rptr: RPtr, pool_keyhash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let pool_keyhash = pool_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = StakeDelegation::new(stake_credential, pool_keyhash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeDeregistration::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeDeregistration::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeDeregistration::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.coin();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_new(stake_credential_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let result = StakeDeregistration::new(stake_credential);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_new_with_coin(stake_credential_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = StakeDeregistration::new_with_coin(stake_credential, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_deregistration_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeDeregistration>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn stake_registration_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeRegistration::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeRegistration::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeRegistration::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.coin();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_new(stake_credential_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let result = StakeRegistration::new(stake_credential);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_new_with_coin(stake_credential_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = StakeRegistration::new_with_coin(stake_credential, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistration>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeRegistrationAndDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeRegistrationAndDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_pool_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.pool_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_new(stake_credential_rptr: RPtr, pool_keyhash_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let pool_keyhash = pool_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = StakeRegistrationAndDelegation::new(stake_credential, pool_keyhash, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_registration_and_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeRegistrationAndDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = StakeVoteRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = StakeVoteRegistrationAndDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = StakeVoteRegistrationAndDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_pool_keyhash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.pool_keyhash();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_drep(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.drep();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_new(stake_credential_rptr: RPtr, pool_keyhash_rptr: RPtr, drep_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let pool_keyhash = pool_keyhash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let drep = drep_rptr.typed_ref::<DRep>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = StakeVoteRegistrationAndDelegation::new(stake_credential, pool_keyhash, drep, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn stake_vote_registration_and_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<StakeVoteRegistrationAndDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn strings_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Strings::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn strings_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Strings>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn strings_get(self_rptr: RPtr, index_long: i64, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Strings>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn strings_add(self_rptr: RPtr, elem_str: CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Strings>()?;
    let elem : String = elem_str.into_str();
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockExpiry>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TimelockExpiry::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockExpiry>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TimelockExpiry::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockExpiry>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TimelockExpiry::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_slot(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockExpiry>()?;
    let result = self_ref.slot().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_slot_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockExpiry>()?;
    let result = self_ref.slot_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_new(slot_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot  = slot_long as u32;
    let result = TimelockExpiry::new(slot);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_expiry_new_timelockexpiry(slot_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot = slot_rptr.typed_ref::<BigNum>()?;
    let result = TimelockExpiry::new_timelockexpiry(slot);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn timelock_start_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockStart>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TimelockStart::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockStart>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TimelockStart::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockStart>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TimelockStart::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_slot(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockStart>()?;
    let result = self_ref.slot().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_slot_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TimelockStart>()?;
    let result = self_ref.slot_bignum();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_new(slot_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot  = slot_long as u32;
    let result = TimelockStart::new(slot);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn timelock_start_new_timelockstart(slot_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let slot = slot_rptr.typed_ref::<BigNum>()?;
    let result = TimelockStart::new_timelockstart(slot);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Transaction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Transaction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Transaction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.body();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.witness_set();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_is_valid(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.is_valid();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_auxiliary_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    let result = self_ref.auxiliary_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_set_is_valid(self_rptr: RPtr, valid: bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Transaction>()?;
    self_ref.set_is_valid(valid);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_new(body_rptr: RPtr, witness_set_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let body = body_rptr.typed_ref::<TransactionBody>()?;
    let witness_set = witness_set_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = Transaction::new(body, witness_set, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_new_with_auxiliary_data(body_rptr: RPtr, witness_set_rptr: RPtr, auxiliary_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let body = body_rptr.typed_ref::<TransactionBody>()?;
    let witness_set = witness_set_rptr.typed_ref::<TransactionWitnessSet>()?;
    let auxiliary_data = auxiliary_data_rptr.typed_ref::<AuxiliaryData>()?.clone();
    let result = Transaction::new(body, witness_set, Some(auxiliary_data));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn transaction_batch_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBatch>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_batch_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBatch>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_batch_list_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBatchList>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_batch_list_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBatchList>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionBodies::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionBodies::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionBodies::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionBodies::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_bodies_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBodies>()?;
    let elem = elem_rptr.typed_ref::<TransactionBody>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_body_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionBody::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionBody::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionBody::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_outputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.outputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_fee(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.fee();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_ttl(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.ttl().into_result()?;
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_ttl_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.ttl_bignum();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_ttl(self_rptr: RPtr, ttl_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let ttl = ttl_rptr.typed_ref::<BigNum>()?;
    self_ref.set_ttl(ttl);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_remove_ttl(self_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    self_ref.remove_ttl();
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_certs(self_rptr: RPtr, certs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let certs = certs_rptr.typed_ref::<Certificates>()?;
    self_ref.set_certs(certs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_certs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.certs();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_withdrawals(self_rptr: RPtr, withdrawals_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let withdrawals = withdrawals_rptr.typed_ref::<Withdrawals>()?;
    self_ref.set_withdrawals(withdrawals);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_withdrawals(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.withdrawals();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_update(self_rptr: RPtr, update_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let update = update_rptr.typed_ref::<Update>()?;
    self_ref.set_update(update);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_update(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.update();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_auxiliary_data_hash(self_rptr: RPtr, auxiliary_data_hash_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let auxiliary_data_hash = auxiliary_data_hash_rptr.typed_ref::<AuxiliaryDataHash>()?;
    self_ref.set_auxiliary_data_hash(auxiliary_data_hash);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_auxiliary_data_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.auxiliary_data_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_validity_start_interval(self_rptr: RPtr, validity_start_interval_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let validity_start_interval  = validity_start_interval_long as u32;
    self_ref.set_validity_start_interval(validity_start_interval);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_validity_start_interval_bignum(self_rptr: RPtr, validity_start_interval_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let validity_start_interval = validity_start_interval_rptr.typed_ref::<BigNum>()?;
    self_ref.set_validity_start_interval_bignum(validity_start_interval);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_validity_start_interval_bignum(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.validity_start_interval_bignum();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_validity_start_interval(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.validity_start_interval().into_result()?;
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_mint(self_rptr: RPtr, mint_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let mint = mint_rptr.typed_ref::<Mint>()?;
    self_ref.set_mint(mint);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_mint(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.mint();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_reference_inputs(self_rptr: RPtr, reference_inputs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let reference_inputs = reference_inputs_rptr.typed_ref::<TransactionInputs>()?;
    self_ref.set_reference_inputs(reference_inputs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_reference_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.reference_inputs();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_script_data_hash(self_rptr: RPtr, script_data_hash_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let script_data_hash = script_data_hash_rptr.typed_ref::<ScriptDataHash>()?;
    self_ref.set_script_data_hash(script_data_hash);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_script_data_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.script_data_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_collateral(self_rptr: RPtr, collateral_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let collateral = collateral_rptr.typed_ref::<TransactionInputs>()?;
    self_ref.set_collateral(collateral);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_collateral(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.collateral();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_required_signers(self_rptr: RPtr, required_signers_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let required_signers = required_signers_rptr.typed_ref::<Ed25519KeyHashes>()?;
    self_ref.set_required_signers(required_signers);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_required_signers(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.required_signers();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_network_id(self_rptr: RPtr, network_id_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let network_id = network_id_rptr.typed_ref::<NetworkId>()?;
    self_ref.set_network_id(network_id);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_network_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.network_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_collateral_return(self_rptr: RPtr, collateral_return_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let collateral_return = collateral_return_rptr.typed_ref::<TransactionOutput>()?;
    self_ref.set_collateral_return(collateral_return);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_collateral_return(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.collateral_return();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_total_collateral(self_rptr: RPtr, total_collateral_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let total_collateral = total_collateral_rptr.typed_ref::<BigNum>()?;
    self_ref.set_total_collateral(total_collateral);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_total_collateral(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.total_collateral();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_voting_procedures(self_rptr: RPtr, voting_procedures_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let voting_procedures = voting_procedures_rptr.typed_ref::<VotingProcedures>()?;
    self_ref.set_voting_procedures(voting_procedures);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_voting_procedures(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.voting_procedures();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_voting_proposals(self_rptr: RPtr, voting_proposals_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let voting_proposals = voting_proposals_rptr.typed_ref::<VotingProposals>()?;
    self_ref.set_voting_proposals(voting_proposals);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_voting_proposals(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.voting_proposals();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_donation(self_rptr: RPtr, donation_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let donation = donation_rptr.typed_ref::<BigNum>()?;
    self_ref.set_donation(donation);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_donation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.donation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_set_current_treasury_value(self_rptr: RPtr, current_treasury_value_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let current_treasury_value = current_treasury_value_rptr.typed_ref::<BigNum>()?;
    self_ref.set_current_treasury_value(current_treasury_value);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_current_treasury_value(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBody>()?;
    let result = self_ref.current_treasury_value();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_new(inputs_rptr: RPtr, outputs_rptr: RPtr, fee_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let inputs = inputs_rptr.typed_ref::<TransactionInputs>()?;
    let outputs = outputs_rptr.typed_ref::<TransactionOutputs>()?;
    let fee = fee_rptr.typed_ref::<BigNum>()?;
    let result = TransactionBody::new(inputs, outputs, fee, None);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_body_new_with_ttl(inputs_rptr: RPtr, outputs_rptr: RPtr, fee_rptr: RPtr, ttl_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let inputs = inputs_rptr.typed_ref::<TransactionInputs>()?;
    let outputs = outputs_rptr.typed_ref::<TransactionOutputs>()?;
    let fee = fee_rptr.typed_ref::<BigNum>()?;
    let ttl  = ttl_long as u32;
    let result = TransactionBody::new(inputs, outputs, fee, Some(ttl));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_body_new_tx_body(inputs_rptr: RPtr, outputs_rptr: RPtr, fee_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let inputs = inputs_rptr.typed_ref::<TransactionInputs>()?;
    let outputs = outputs_rptr.typed_ref::<TransactionOutputs>()?;
    let fee = fee_rptr.typed_ref::<BigNum>()?;
    let result = TransactionBody::new_tx_body(inputs, outputs, fee);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_inputs_from(self_rptr: RPtr, inputs_rptr: RPtr, strategy_int: i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let inputs = inputs_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let strategy = strategy_int.to_enum()?;
    self_ref.add_inputs_from(inputs, strategy).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_inputs(self_rptr: RPtr, inputs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let inputs = inputs_rptr.typed_ref::<TxInputsBuilder>()?;
    self_ref.set_inputs(inputs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_collateral(self_rptr: RPtr, collateral_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let collateral = collateral_rptr.typed_ref::<TxInputsBuilder>()?;
    self_ref.set_collateral(collateral);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_collateral_return(self_rptr: RPtr, collateral_return_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let collateral_return = collateral_return_rptr.typed_ref::<TransactionOutput>()?;
    self_ref.set_collateral_return(collateral_return);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_collateral_return_and_total(self_rptr: RPtr, collateral_return_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let collateral_return = collateral_return_rptr.typed_ref::<TransactionOutput>()?;
    self_ref.set_collateral_return_and_total(collateral_return).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_total_collateral(self_rptr: RPtr, total_collateral_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let total_collateral = total_collateral_rptr.typed_ref::<BigNum>()?;
    self_ref.set_total_collateral(total_collateral);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_total_collateral_and_return(self_rptr: RPtr, total_collateral_rptr: RPtr, return_address_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let total_collateral = total_collateral_rptr.typed_ref::<BigNum>()?;
    let return_address = return_address_rptr.typed_ref::<Address>()?;
    self_ref.set_total_collateral_and_return(total_collateral, return_address).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_reference_input(self_rptr: RPtr, reference_input_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let reference_input = reference_input_rptr.typed_ref::<TransactionInput>()?;
    self_ref.add_reference_input(reference_input);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_key_input(self_rptr: RPtr, hash_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let hash = hash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_key_input(hash, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_native_script_input(self_rptr: RPtr, script_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let script = script_rptr.typed_ref::<NativeScript>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_native_script_input(script, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_plutus_script_input(self_rptr: RPtr, witness_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_plutus_script_input(witness, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_bootstrap_input(self_rptr: RPtr, hash_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let hash = hash_rptr.typed_ref::<ByronAddress>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_bootstrap_input(hash, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_regular_input(self_rptr: RPtr, address_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_regular_input(address, input, amount).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_native_input_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_native_input_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_plutus_input_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_plutus_input_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_fee_for_input(self_rptr: RPtr, address_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    let result = self_ref.fee_for_input(address, input, amount).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_output(self_rptr: RPtr, output_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let output = output_rptr.typed_ref::<TransactionOutput>()?;
    self_ref.add_output(output).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_fee_for_output(self_rptr: RPtr, output_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let output = output_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.fee_for_output(output).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_fee(self_rptr: RPtr, fee_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let fee = fee_rptr.typed_ref::<BigNum>()?;
    self_ref.set_fee(fee);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_ttl(self_rptr: RPtr, ttl_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let ttl  = ttl_long as u32;
    self_ref.set_ttl(ttl);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_ttl_bignum(self_rptr: RPtr, ttl_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let ttl = ttl_rptr.typed_ref::<BigNum>()?;
    self_ref.set_ttl_bignum(ttl);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_validity_start_interval(self_rptr: RPtr, validity_start_interval_long: i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let validity_start_interval  = validity_start_interval_long as u32;
    self_ref.set_validity_start_interval(validity_start_interval);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_validity_start_interval_bignum(self_rptr: RPtr, validity_start_interval_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let validity_start_interval = validity_start_interval_rptr.typed_ref::<BigNum>()?.clone();
    self_ref.set_validity_start_interval_bignum(validity_start_interval);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_certs(self_rptr: RPtr, certs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let certs = certs_rptr.typed_ref::<Certificates>()?;
    self_ref.set_certs(certs).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_certs_builder(self_rptr: RPtr, certs_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let certs = certs_rptr.typed_ref::<CertificatesBuilder>()?;
    self_ref.set_certs_builder(certs);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_withdrawals(self_rptr: RPtr, withdrawals_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let withdrawals = withdrawals_rptr.typed_ref::<Withdrawals>()?;
    self_ref.set_withdrawals(withdrawals).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_withdrawals_builder(self_rptr: RPtr, withdrawals_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let withdrawals = withdrawals_rptr.typed_ref::<WithdrawalsBuilder>()?;
    self_ref.set_withdrawals_builder(withdrawals);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_voting_builder(self_rptr: RPtr, voting_builder_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let voting_builder = voting_builder_rptr.typed_ref::<VotingBuilder>()?;
    self_ref.set_voting_builder(voting_builder);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_voting_proposal_builder(self_rptr: RPtr, voting_proposal_builder_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let voting_proposal_builder = voting_proposal_builder_rptr.typed_ref::<VotingProposalBuilder>()?;
    self_ref.set_voting_proposal_builder(voting_proposal_builder);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_auxiliary_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_auxiliary_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_auxiliary_data(self_rptr: RPtr, auxiliary_data_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let auxiliary_data = auxiliary_data_rptr.typed_ref::<AuxiliaryData>()?;
    self_ref.set_auxiliary_data(auxiliary_data);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_metadata(self_rptr: RPtr, metadata_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let metadata = metadata_rptr.typed_ref::<GeneralTransactionMetadata>()?;
    self_ref.set_metadata(metadata);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_metadatum(self_rptr: RPtr, key_rptr: RPtr, val_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let key = key_rptr.typed_ref::<BigNum>()?;
    let val = val_rptr.typed_ref::<TransactionMetadatum>()?;
    self_ref.add_metadatum(key, val);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_json_metadatum(self_rptr: RPtr, key_rptr: RPtr, val_str: CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let key = key_rptr.typed_ref::<BigNum>()?;
    let val : String = val_str.into_str();
    self_ref.add_json_metadatum(key, val).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_json_metadatum_with_schema(self_rptr: RPtr, key_rptr: RPtr, val_str: CharPtr, schema_int: i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let key = key_rptr.typed_ref::<BigNum>()?;
    let val : String = val_str.into_str();
    let schema = schema_int.to_enum()?;
    self_ref.add_json_metadatum_with_schema(key, val, schema).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_mint_builder(self_rptr: RPtr, mint_builder_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let mint_builder = mint_builder_rptr.typed_ref::<MintBuilder>()?;
    self_ref.set_mint_builder(mint_builder);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_mint_builder(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_mint_builder();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_mint(self_rptr: RPtr, mint_rptr: RPtr, mint_scripts_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let mint = mint_rptr.typed_ref::<Mint>()?;
    let mint_scripts = mint_scripts_rptr.typed_ref::<NativeScripts>()?;
    self_ref.set_mint(mint, mint_scripts).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_mint(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_mint();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_mint_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_mint_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_mint_asset(self_rptr: RPtr, policy_script_rptr: RPtr, mint_assets_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let policy_script = policy_script_rptr.typed_ref::<NativeScript>()?;
    let mint_assets = mint_assets_rptr.typed_ref::<MintAssets>()?;
    self_ref.set_mint_asset(policy_script, mint_assets);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_mint_asset(self_rptr: RPtr, policy_script_rptr: RPtr, asset_name_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let policy_script = policy_script_rptr.typed_ref::<NativeScript>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let amount = amount_rptr.typed_ref::<Int>()?;
    self_ref.add_mint_asset(policy_script, asset_name, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_mint_asset_and_output(self_rptr: RPtr, policy_script_rptr: RPtr, asset_name_rptr: RPtr, amount_rptr: RPtr, output_builder_rptr: RPtr, output_coin_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let policy_script = policy_script_rptr.typed_ref::<NativeScript>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let amount = amount_rptr.typed_ref::<Int>()?;
    let output_builder = output_builder_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let output_coin = output_coin_rptr.typed_ref::<BigNum>()?;
    self_ref.add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_mint_asset_and_output_min_required_coin(self_rptr: RPtr, policy_script_rptr: RPtr, asset_name_rptr: RPtr, amount_rptr: RPtr, output_builder_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let policy_script = policy_script_rptr.typed_ref::<NativeScript>()?;
    let asset_name = asset_name_rptr.typed_ref::<AssetName>()?;
    let amount = amount_rptr.typed_ref::<Int>()?;
    let output_builder = output_builder_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    self_ref.add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_extra_witness_datum(self_rptr: RPtr, datum_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let datum = datum_rptr.typed_ref::<PlutusData>()?;
    self_ref.add_extra_witness_datum(datum);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_extra_witness_datums(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_extra_witness_datums();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_donation(self_rptr: RPtr, donation_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let donation = donation_rptr.typed_ref::<BigNum>()?;
    self_ref.set_donation(donation);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_donation(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_donation();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_current_treasury_value(self_rptr: RPtr, current_treasury_value_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let current_treasury_value = current_treasury_value_rptr.typed_ref::<BigNum>()?;
    self_ref.set_current_treasury_value(current_treasury_value).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_current_treasury_value(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_current_treasury_value();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_new(cfg_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let cfg = cfg_rptr.typed_ref::<TransactionBuilderConfig>()?;
    let result = TransactionBuilder::new(cfg);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_reference_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_reference_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_explicit_input(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_explicit_input().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_implicit_input(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_implicit_input().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_total_input(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_total_input().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_total_output(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_total_output().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_explicit_output(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_explicit_output().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_deposit().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_get_fee_if_set(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.get_fee_if_set();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_change_if_needed(self_rptr: RPtr, address_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let result = self_ref.add_change_if_needed(address).into_result()?;
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_change_if_needed_with_datum(self_rptr: RPtr, address_rptr: RPtr, plutus_data_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let plutus_data = plutus_data_rptr.typed_ref::<OutputDatum>()?;
    let result = self_ref.add_change_if_needed_with_datum(address, plutus_data).into_result()?;
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_calc_script_data_hash(self_rptr: RPtr, cost_models_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let cost_models = cost_models_rptr.typed_ref::<Costmdls>()?;
    self_ref.calc_script_data_hash(cost_models).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_set_script_data_hash(self_rptr: RPtr, hash_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let hash = hash_rptr.typed_ref::<ScriptDataHash>()?;
    self_ref.set_script_data_hash(hash);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_remove_script_data_hash(self_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    self_ref.remove_script_data_hash();
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_add_required_signer(self_rptr: RPtr, key_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let key = key_rptr.typed_ref::<Ed25519KeyHash>()?;
    self_ref.add_required_signer(key);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_full_size(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.full_size().into_result()?;
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_output_sizes(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.output_sizes();
    Ok::<CharPtr, String>(usize_array_to_base64(&result).into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.build().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_build_tx(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.build_tx().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_build_tx_unsafe(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.build_tx_unsafe().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_min_fee(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilder>()?;
    let result = self_ref.min_fee().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}




#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionBuilderConfigBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_fee_algo(self_rptr: RPtr, fee_algo_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let fee_algo = fee_algo_rptr.typed_ref::<LinearFee>()?;
    let result = self_ref.fee_algo(fee_algo);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_coins_per_utxo_byte(self_rptr: RPtr, coins_per_utxo_byte_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let coins_per_utxo_byte = coins_per_utxo_byte_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.coins_per_utxo_byte(coins_per_utxo_byte);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_ex_unit_prices(self_rptr: RPtr, ex_unit_prices_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let ex_unit_prices = ex_unit_prices_rptr.typed_ref::<ExUnitPrices>()?;
    let result = self_ref.ex_unit_prices(ex_unit_prices);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_pool_deposit(self_rptr: RPtr, pool_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.pool_deposit(pool_deposit);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_key_deposit(self_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.key_deposit(key_deposit);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_max_value_size(self_rptr: RPtr, max_value_size_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let max_value_size  = max_value_size_long as u32;
    let result = self_ref.max_value_size(max_value_size);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_max_tx_size(self_rptr: RPtr, max_tx_size_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let max_tx_size  = max_tx_size_long as u32;
    let result = self_ref.max_tx_size(max_tx_size);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_prefer_pure_change(self_rptr: RPtr, prefer_pure_change: bool, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let result = self_ref.prefer_pure_change(prefer_pure_change);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_builder_config_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionBuilderConfigBuilder>()?;
    let result = self_ref.build().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = TransactionHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = TransactionHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_input_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInput>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionInput::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInput>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionInput::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInput>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionInput::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_transaction_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInput>()?;
    let result = self_ref.transaction_id();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_index(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInput>()?;
    let result = self_ref.index();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_input_new(transaction_id_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let transaction_id = transaction_id_rptr.typed_ref::<TransactionHash>()?;
    let index  = index_long as u32;
    let result = TransactionInput::new(transaction_id, index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionInputs::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionInputs::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionInputs::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionInputs::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let elem = elem_rptr.typed_ref::<TransactionInput>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_inputs_to_option(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionInputs>()?;
    let result = self_ref.to_option();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionMetadatum::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionMetadatum::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_map(map_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let map = map_rptr.typed_ref::<MetadataMap>()?;
    let result = TransactionMetadatum::new_map(map);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_list(list_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let list = list_rptr.typed_ref::<MetadataList>()?;
    let result = TransactionMetadatum::new_list(list);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_int(int_value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let int_value = int_value_rptr.typed_ref::<Int>()?;
    let result = TransactionMetadatum::new_int(int_value);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionMetadatum::new_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_new_text(text_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let text : String = text_str.into_str();
    let result = TransactionMetadatum::new_text(text).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_as_map(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.as_map().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_as_list(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.as_list().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_as_int(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.as_int().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_as_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.as_bytes().into_result()?;
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_as_text(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = self_ref.as_text().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionMetadatumLabels::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionMetadatumLabels::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionMetadatumLabels::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatumLabels>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatumLabels>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_metadatum_labels_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionMetadatumLabels>()?;
    let elem = elem_rptr.typed_ref::<BigNum>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_output_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionOutput::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionOutput::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionOutput::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_address(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.address();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.amount();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_data_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.data_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_plutus_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.plutus_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_script_ref(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.script_ref();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_set_script_ref(self_rptr: RPtr, script_ref_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let script_ref = script_ref_rptr.typed_ref::<ScriptRef>()?;
    self_ref.set_script_ref(script_ref);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_set_plutus_data(self_rptr: RPtr, data_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let data = data_rptr.typed_ref::<PlutusData>()?;
    self_ref.set_plutus_data(data);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_set_data_hash(self_rptr: RPtr, data_hash_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let data_hash = data_hash_rptr.typed_ref::<DataHash>()?;
    self_ref.set_data_hash(data_hash);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_has_plutus_data(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.has_plutus_data();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_has_data_hash(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.has_data_hash();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_has_script_ref(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.has_script_ref();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_new(address_rptr: RPtr, amount_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let address = address_rptr.typed_ref::<Address>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    let result = TransactionOutput::new(address, amount);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_serialization_format(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutput>()?;
    let result = self_ref.serialization_format();
    Ok::<Option<i32>, String>(result.map(|v| v as i32))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount_builder_with_value(self_rptr: RPtr, amount_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    let result = self_ref.with_value(amount);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount_builder_with_coin(self_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.with_coin(coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount_builder_with_coin_and_asset(self_rptr: RPtr, coin_rptr: RPtr, multiasset_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let multiasset = multiasset_rptr.typed_ref::<MultiAsset>()?;
    let result = self_ref.with_coin_and_asset(coin, multiasset);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount_builder_with_asset_and_min_required_coin_by_utxo_cost(self_rptr: RPtr, multiasset_rptr: RPtr, data_cost_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let multiasset = multiasset_rptr.typed_ref::<MultiAsset>()?;
    let data_cost = data_cost_rptr.typed_ref::<DataCost>()?;
    let result = self_ref.with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_amount_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputAmountBuilder>()?;
    let result = self_ref.build().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionOutputBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_with_address(self_rptr: RPtr, address_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let result = self_ref.with_address(address);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_with_data_hash(self_rptr: RPtr, data_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputBuilder>()?;
    let data_hash = data_hash_rptr.typed_ref::<DataHash>()?;
    let result = self_ref.with_data_hash(data_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_with_plutus_data(self_rptr: RPtr, data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputBuilder>()?;
    let data = data_rptr.typed_ref::<PlutusData>()?;
    let result = self_ref.with_plutus_data(data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_with_script_ref(self_rptr: RPtr, script_ref_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputBuilder>()?;
    let script_ref = script_ref_rptr.typed_ref::<ScriptRef>()?;
    let result = self_ref.with_script_ref(script_ref);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_output_builder_next(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputBuilder>()?;
    let result = self_ref.next().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionOutputs::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionOutputs::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionOutputs::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionOutputs::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_outputs_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionOutputs>()?;
    let elem = elem_rptr.typed_ref::<TransactionOutput>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionUnspentOutput::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionUnspentOutput::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionUnspentOutput::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_new(input_rptr: RPtr, output_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let output = output_rptr.typed_ref::<TransactionOutput>()?;
    let result = TransactionUnspentOutput::new(input, output);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_input(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_ref.input();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_output_output(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutput>()?;
    let result = self_ref.output();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionUnspentOutputs::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionUnspentOutputs::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_unspent_outputs_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionUnspentOutputs>()?;
    let elem = elem_rptr.typed_ref::<TransactionUnspentOutput>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionWitnessSet::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionWitnessSet::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionWitnessSet::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_vkeys(self_rptr: RPtr, vkeys_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let vkeys = vkeys_rptr.typed_ref::<Vkeywitnesses>()?;
    self_ref.set_vkeys(vkeys);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_vkeys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.vkeys();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_native_scripts(self_rptr: RPtr, native_scripts_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let native_scripts = native_scripts_rptr.typed_ref::<NativeScripts>()?;
    self_ref.set_native_scripts(native_scripts);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.native_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_bootstraps(self_rptr: RPtr, bootstraps_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let bootstraps = bootstraps_rptr.typed_ref::<BootstrapWitnesses>()?;
    self_ref.set_bootstraps(bootstraps);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_bootstraps(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.bootstraps();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_plutus_scripts(self_rptr: RPtr, plutus_scripts_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let plutus_scripts = plutus_scripts_rptr.typed_ref::<PlutusScripts>()?;
    self_ref.set_plutus_scripts(plutus_scripts);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_plutus_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.plutus_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_plutus_data(self_rptr: RPtr, plutus_data_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let plutus_data = plutus_data_rptr.typed_ref::<PlutusList>()?;
    self_ref.set_plutus_data(plutus_data);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_plutus_data(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.plutus_data();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_set_redeemers(self_rptr: RPtr, redeemers_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let redeemers = redeemers_rptr.typed_ref::<Redeemers>()?;
    self_ref.set_redeemers(redeemers);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_redeemers(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSet>()?;
    let result = self_ref.redeemers();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_set_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionWitnessSet::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TransactionWitnessSets::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TransactionWitnessSets::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TransactionWitnessSets::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TransactionWitnessSets::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn transaction_witness_sets_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TransactionWitnessSets>()?;
    let elem = elem_rptr.typed_ref::<TransactionWitnessSet>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TreasuryWithdrawals::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TreasuryWithdrawals::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let key = key_rptr.typed_ref::<RewardAddress>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let key = key_rptr.typed_ref::<RewardAddress>()?;
    let value = value_rptr.typed_ref::<BigNum>()?;
    self_ref.insert(key, value);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = TreasuryWithdrawalsAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = TreasuryWithdrawalsAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = TreasuryWithdrawalsAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_withdrawals(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_ref.withdrawals();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_policy_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TreasuryWithdrawalsAction>()?;
    let result = self_ref.policy_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_new(withdrawals_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let withdrawals = withdrawals_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let result = TreasuryWithdrawalsAction::new(withdrawals);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn treasury_withdrawals_action_new_with_policy_hash(withdrawals_rptr: RPtr, policy_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let withdrawals = withdrawals_rptr.typed_ref::<TreasuryWithdrawals>()?;
    let policy_hash = policy_hash_rptr.typed_ref::<ScriptHash>()?;
    let result = TreasuryWithdrawalsAction::new_with_policy_hash(withdrawals, policy_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn tx_builder_constants_plutus_default_cost_models(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_default_cost_models();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_builder_constants_plutus_alonzo_cost_models(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_alonzo_cost_models();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_builder_constants_plutus_vasil_cost_models(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TxBuilderConstants::plutus_vasil_cost_models();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = TxInputsBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_key_input(self_rptr: RPtr, hash_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let hash = hash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_key_input(hash, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_native_script_input(self_rptr: RPtr, script_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let script = script_rptr.typed_ref::<NativeScript>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_native_script_input(script, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_plutus_script_input(self_rptr: RPtr, witness_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_plutus_script_input(witness, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_bootstrap_input(self_rptr: RPtr, hash_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let hash = hash_rptr.typed_ref::<ByronAddress>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_bootstrap_input(hash, input, amount);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_regular_input(self_rptr: RPtr, address_rptr: RPtr, input_rptr: RPtr, amount_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let address = address_rptr.typed_ref::<Address>()?;
    let input = input_rptr.typed_ref::<TransactionInput>()?;
    let amount = amount_rptr.typed_ref::<Value>()?;
    self_ref.add_regular_input(address, input, amount).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_get_native_input_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.get_native_input_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_get_plutus_input_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.get_plutus_input_scripts();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_required_signer(self_rptr: RPtr, key_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let key = key_rptr.typed_ref::<Ed25519KeyHash>()?;
    self_ref.add_required_signer(key);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_add_required_signers(self_rptr: RPtr, keys_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let keys = keys_rptr.typed_ref::<Ed25519KeyHashes>()?;
    self_ref.add_required_signers(keys);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_total_value(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.total_value().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn tx_inputs_builder_inputs_option(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<TxInputsBuilder>()?;
    let result = self_ref.inputs_option();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn u_r_l_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<URL>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = URL::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<URL>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = URL::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<URL>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = URL::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_new(url_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let url : String = url_str.into_str();
    let result = URL::new(url).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn u_r_l_url(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<URL>()?;
    let result = self_ref.url();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn unit_interval_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UnitInterval>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = UnitInterval::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UnitInterval>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = UnitInterval::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UnitInterval>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = UnitInterval::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_numerator(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UnitInterval>()?;
    let result = self_ref.numerator();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_denominator(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UnitInterval>()?;
    let result = self_ref.denominator();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn unit_interval_new(numerator_rptr: RPtr, denominator_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let numerator = numerator_rptr.typed_ref::<BigNum>()?;
    let denominator = denominator_rptr.typed_ref::<BigNum>()?;
    let result = UnitInterval::new(numerator, denominator);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn update_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Update>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Update::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Update>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Update::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Update>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Update::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_proposed_protocol_parameter_updates(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Update>()?;
    let result = self_ref.proposed_protocol_parameter_updates();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_epoch(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Update>()?;
    let result = self_ref.epoch();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_new(proposed_protocol_parameter_updates_rptr: RPtr, epoch_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let proposed_protocol_parameter_updates = proposed_protocol_parameter_updates_rptr.typed_ref::<ProposedProtocolParameterUpdates>()?;
    let epoch  = epoch_long as u32;
    let result = Update::new(proposed_protocol_parameter_updates, epoch);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn update_committee_action_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = UpdateCommitteeAction::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = UpdateCommitteeAction::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = UpdateCommitteeAction::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_gov_action_id(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.gov_action_id();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_committee(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.committee();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_members_to_remove(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<UpdateCommitteeAction>()?;
    let result = self_ref.members_to_remove();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_new(committee_rptr: RPtr, members_to_remove_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let committee = committee_rptr.typed_ref::<Committee>()?;
    let members_to_remove = members_to_remove_rptr.typed_ref::<Credentials>()?;
    let result = UpdateCommitteeAction::new(committee, members_to_remove);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn update_committee_action_new_with_action_id(gov_action_id_rptr: RPtr, committee_rptr: RPtr, members_to_remove_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let committee = committee_rptr.typed_ref::<Committee>()?;
    let members_to_remove = members_to_remove_rptr.typed_ref::<Credentials>()?;
    let result = UpdateCommitteeAction::new_with_action_id(gov_action_id, committee, members_to_remove);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFCert>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VRFCert::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFCert>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VRFCert::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFCert>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VRFCert::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_output(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFCert>()?;
    let result = self_ref.output();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_proof(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFCert>()?;
    let result = self_ref.proof();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_cert_new(output_data: *const u8, output_len: usize, proof_data: *const u8, proof_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let output = from_raw_parts(output_data, output_len).to_vec();
    let proof = from_raw_parts(proof_data, proof_len).to_vec();
    let result = VRFCert::new(output, proof).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VRFKeyHash::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFKeyHash>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFKeyHash>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = VRFKeyHash::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFKeyHash>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_key_hash_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = VRFKeyHash::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VRFVKey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFVKey>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_to_bech32(self_rptr: RPtr, prefix_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFVKey>()?;
    let prefix: &str = prefix_str.into_str();
    let result = self_ref.to_bech32(prefix).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_from_bech32(bech_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bech_str: &str = bech_str_str.into_str();
    let result = VRFVKey::from_bech32(bech_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VRFVKey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn v_r_f_v_key_from_hex(hex_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex: &str = hex_str.into_str();
    let result = VRFVKey::from_hex(hex).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn value_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Value::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Value::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Value::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_new(coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = Value::new(coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_new_from_assets(multiasset_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let multiasset = multiasset_rptr.typed_ref::<MultiAsset>()?;
    let result = Value::new_from_assets(multiasset);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_new_with_assets(coin_rptr: RPtr, multiasset_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let multiasset = multiasset_rptr.typed_ref::<MultiAsset>()?;
    let result = Value::new_with_assets(coin, multiasset);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_zero(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Value::zero();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_is_zero(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.is_zero();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_set_coin(self_rptr: RPtr, coin_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    self_ref.set_coin(coin);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_multiasset(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let result = self_ref.multiasset();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_set_multiasset(self_rptr: RPtr, multiasset_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let multiasset = multiasset_rptr.typed_ref::<MultiAsset>()?;
    self_ref.set_multiasset(multiasset);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_checked_add(self_rptr: RPtr, rhs_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let rhs = rhs_rptr.typed_ref::<Value>()?;
    let result = self_ref.checked_add(rhs).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_checked_sub(self_rptr: RPtr, rhs_value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let rhs_value = rhs_value_rptr.typed_ref::<Value>()?;
    let result = self_ref.checked_sub(rhs_value).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_clamped_sub(self_rptr: RPtr, rhs_value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let rhs_value = rhs_value_rptr.typed_ref::<Value>()?;
    let result = self_ref.clamped_sub(rhs_value);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn value_compare(self_rptr: RPtr, rhs_value_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Value>()?;
    let rhs_value = rhs_value_rptr.typed_ref::<Value>()?;
    let result = self_ref.compare(rhs_value);
    Ok::<Option<i64>, String>(result.map(|v| v as i64))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn vkey_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkey>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Vkey::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkey>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Vkey::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkey>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Vkey::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_new(pk_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let pk = pk_rptr.typed_ref::<PublicKey>()?;
    let result = Vkey::new(pk);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkey_public_key(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkey>()?;
    let result = self_ref.public_key();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn vkeys_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Vkeys::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeys_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeys>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeys_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeys>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeys_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeys>()?;
    let elem = elem_rptr.typed_ref::<Vkey>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn vkeywitness_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitness>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Vkeywitness::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitness>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Vkeywitness::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitness>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Vkeywitness::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_new(vkey_rptr: RPtr, signature_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vkey = vkey_rptr.typed_ref::<Vkey>()?;
    let signature = signature_rptr.typed_ref::<Ed25519Signature>()?;
    let result = Vkeywitness::new(vkey, signature);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_vkey(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitness>()?;
    let result = self_ref.vkey();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitness_signature(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitness>()?;
    let result = self_ref.signature();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Vkeywitnesses::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Vkeywitnesses::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Vkeywitnesses::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Vkeywitnesses::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vkeywitnesses_add(self_rptr: RPtr, elem_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Vkeywitnesses>()?;
    let elem = elem_rptr.typed_ref::<Vkeywitness>()?;
    self_ref.add(elem);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn vote_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VoteDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VoteDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VoteDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_drep(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.drep();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_new(stake_credential_rptr: RPtr, drep_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let drep = drep_rptr.typed_ref::<DRep>()?;
    let result = VoteDelegation::new(stake_credential, drep);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VoteRegistrationAndDelegation::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VoteRegistrationAndDelegation::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VoteRegistrationAndDelegation::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_stake_credential(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.stake_credential();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_drep(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.drep();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_coin(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.coin();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_new(stake_credential_rptr: RPtr, drep_rptr: RPtr, coin_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let stake_credential = stake_credential_rptr.typed_ref::<Credential>()?;
    let drep = drep_rptr.typed_ref::<DRep>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let result = VoteRegistrationAndDelegation::new(stake_credential, drep, coin);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn vote_registration_and_delegation_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VoteRegistrationAndDelegation>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voter_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Voter::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Voter::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Voter::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_new_constitutional_committee_hot_key(cred_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let cred = cred_rptr.typed_ref::<Credential>()?;
    let result = Voter::new_constitutional_committee_hot_key(cred);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_new_drep(cred_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let cred = cred_rptr.typed_ref::<Credential>()?;
    let result = Voter::new_drep(cred);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_new_staking_pool(key_hash_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let key_hash = key_hash_rptr.typed_ref::<Ed25519KeyHash>()?;
    let result = Voter::new_staking_pool(key_hash);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_constitutional_committee_hot_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_constitutional_committee_hot_cred();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_drep_cred(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_drep_cred();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_staking_pool_key_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_staking_pool_key_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_has_script_credentials(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.has_script_credentials();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voter_to_key_hash(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voter>()?;
    let result = self_ref.to_key_hash();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voters_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voters>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voters_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Voters::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voters_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Voters::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voters_add(self_rptr: RPtr, voter_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voters>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    self_ref.add(voter);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voters_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voters>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voters_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Voters>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = VotingBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_add(self_rptr: RPtr, voter_rptr: RPtr, gov_action_id_rptr: RPtr, voting_procedure_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure = voting_procedure_rptr.typed_ref::<VotingProcedure>()?;
    self_ref.add(voter, gov_action_id, voting_procedure).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_add_with_plutus_witness(self_rptr: RPtr, voter_rptr: RPtr, gov_action_id_rptr: RPtr, voting_procedure_rptr: RPtr, witness_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure = voting_procedure_rptr.typed_ref::<VotingProcedure>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    self_ref.add_with_plutus_witness(voter, gov_action_id, voting_procedure, witness).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_add_with_native_script(self_rptr: RPtr, voter_rptr: RPtr, gov_action_id_rptr: RPtr, voting_procedure_rptr: RPtr, native_script_source_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let gov_action_id = gov_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure = voting_procedure_rptr.typed_ref::<VotingProcedure>()?;
    let native_script_source = native_script_source_rptr.typed_ref::<NativeScriptSource>()?;
    self_ref.add_with_native_script(voter, gov_action_id, voting_procedure, native_script_source).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_get_plutus_witnesses(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let result = self_ref.get_plutus_witnesses();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_get_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let result = self_ref.get_native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_has_plutus_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let result = self_ref.has_plutus_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingBuilder>()?;
    let result = self_ref.build();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_procedure_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedure>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VotingProcedure::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedure>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VotingProcedure::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedure>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VotingProcedure::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_new(vote_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vote = vote_int.to_enum()?;
    let result = VotingProcedure::new(vote);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_new_with_anchor(vote_int: i32, anchor_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let vote = vote_int.to_enum()?;
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let result = VotingProcedure::new_with_anchor(vote, anchor);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_vote_kind(self_rptr: RPtr, result: &mut i32, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedure>()?;
    let result = self_ref.vote_kind();
    Ok::<i32, String>(result as i32)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedure_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedure>()?;
    let result = self_ref.anchor();
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_procedures_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VotingProcedures::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VotingProcedures::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VotingProcedures::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = VotingProcedures::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_insert(self_rptr: RPtr, voter_rptr: RPtr, governance_action_id_rptr: RPtr, voting_procedure_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let governance_action_id = governance_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let voting_procedure = voting_procedure_rptr.typed_ref::<VotingProcedure>()?;
    self_ref.insert(voter, governance_action_id, voting_procedure);
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_get(self_rptr: RPtr, voter_rptr: RPtr, governance_action_id_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let governance_action_id = governance_action_id_rptr.typed_ref::<GovernanceActionId>()?;
    let result = self_ref.get(voter, governance_action_id);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_get_voters(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let result = self_ref.get_voters();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_procedures_get_governance_action_ids_by_voter(self_rptr: RPtr, voter_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProcedures>()?;
    let voter = voter_rptr.typed_ref::<Voter>()?;
    let result = self_ref.get_governance_action_ids_by_voter(voter);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_proposal_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VotingProposal::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VotingProposal::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VotingProposal::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_governance_action(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.governance_action();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_anchor(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.anchor();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_reward_account(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.reward_account();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_deposit(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposal>()?;
    let result = self_ref.deposit();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_new(governance_action_rptr: RPtr, anchor_rptr: RPtr, reward_account_rptr: RPtr, deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let governance_action = governance_action_rptr.typed_ref::<GovernanceAction>()?;
    let anchor = anchor_rptr.typed_ref::<Anchor>()?;
    let reward_account = reward_account_rptr.typed_ref::<RewardAddress>()?;
    let deposit = deposit_rptr.typed_ref::<BigNum>()?;
    let result = VotingProposal::new(governance_action, anchor, reward_account, deposit);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = VotingProposalBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_add(self_rptr: RPtr, proposal_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let proposal = proposal_rptr.typed_ref::<VotingProposal>()?;
    self_ref.add(proposal).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_add_with_plutus_witness(self_rptr: RPtr, proposal_rptr: RPtr, witness_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let proposal = proposal_rptr.typed_ref::<VotingProposal>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    self_ref.add_with_plutus_witness(proposal, witness).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_get_plutus_witnesses(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_ref.get_plutus_witnesses();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_has_plutus_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_ref.has_plutus_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposal_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposalBuilder>()?;
    let result = self_ref.build();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn voting_proposals_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = VotingProposals::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = VotingProposals::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = VotingProposals::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = VotingProposals::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_get(self_rptr: RPtr, index_long: i64, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let index  = index_long as usize;
    let result = self_ref.get(index);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn voting_proposals_add(self_rptr: RPtr, proposal_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<VotingProposals>()?;
    let proposal = proposal_rptr.typed_ref::<VotingProposal>()?;
    self_ref.add(proposal);
    Ok(())
  })
  .response(&mut (),  error)
}



#[no_mangle]
pub unsafe extern "C" fn withdrawals_to_bytes(self_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let result = self_ref.to_bytes();
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_from_bytes(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len).to_vec();
    let result = Withdrawals::from_bytes(bytes).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_to_hex(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let result = self_ref.to_hex();
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_from_hex(hex_str_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let hex_str: &str = hex_str_str.into_str();
    let result = Withdrawals::from_hex(hex_str).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_to_json(self_rptr: RPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let result = self_ref.to_json().into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_from_json(json_str: CharPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let result = Withdrawals::from_json(json).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = Withdrawals::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_len(self_rptr: RPtr, result: &mut i64, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let result = self_ref.len();
    Ok::<i64, String>(result as i64)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_insert(self_rptr: RPtr, key_rptr: RPtr, value_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let key = key_rptr.typed_ref::<RewardAddress>()?;
    let value = value_rptr.typed_ref::<BigNum>()?;
    let result = self_ref.insert(key, value);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_get(self_rptr: RPtr, key_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let key = key_rptr.typed_ref::<RewardAddress>()?;
    let result = self_ref.get(key);
    Ok::<Option<RPtr>, String>(result.map(|v| v.rptr()))
  })
  .response_nullable(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_keys(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<Withdrawals>()?;
    let result = self_ref.keys();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_new(result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let result = WithdrawalsBuilder::new();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_add(self_rptr: RPtr, address_rptr: RPtr, coin_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let address = address_rptr.typed_ref::<RewardAddress>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    self_ref.add(address, coin).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_add_with_plutus_witness(self_rptr: RPtr, address_rptr: RPtr, coin_rptr: RPtr, witness_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let address = address_rptr.typed_ref::<RewardAddress>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let witness = witness_rptr.typed_ref::<PlutusWitness>()?;
    self_ref.add_with_plutus_witness(address, coin, witness).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_add_with_native_script(self_rptr: RPtr, address_rptr: RPtr, coin_rptr: RPtr, native_script_source_rptr: RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let address = address_rptr.typed_ref::<RewardAddress>()?;
    let coin = coin_rptr.typed_ref::<BigNum>()?;
    let native_script_source = native_script_source_rptr.typed_ref::<NativeScriptSource>()?;
    self_ref.add_with_native_script(address, coin, native_script_source).into_result()?;
    Ok(())
  })
  .response(&mut (),  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_get_plutus_witnesses(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.get_plutus_witnesses();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_get_ref_inputs(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.get_ref_inputs();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_get_native_scripts(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.get_native_scripts();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_get_total_withdrawals(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.get_total_withdrawals().into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_has_plutus_scripts(self_rptr: RPtr, result: &mut bool, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.has_plutus_scripts();
    Ok::<bool, String>(result)
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn withdrawals_builder_build(self_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let self_ref = self_rptr.typed_ref::<WithdrawalsBuilder>()?;
    let result = self_ref.build();
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn calculate_ex_units_ceil_cost(ex_units_rptr: RPtr, ex_unit_prices_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let ex_units = ex_units_rptr.typed_ref::<ExUnits>()?;
    let ex_unit_prices = ex_unit_prices_rptr.typed_ref::<ExUnitPrices>()?;
    let result = cardano_serialization_lib::calculate_ex_units_ceil_cost(ex_units, ex_unit_prices).into_result()?;
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
    let result = cardano_serialization_lib::create_send_all(address, utxos, config).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_arbitrary_bytes_from_metadatum(metadata_rptr: RPtr, result: &mut DataPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let metadata = metadata_rptr.typed_ref::<TransactionMetadatum>()?;
    let result = cardano_serialization_lib::decode_arbitrary_bytes_from_metadatum(metadata).into_result()?;
    Ok::<DataPtr, String>(result.into())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_metadatum_to_json_str(metadatum_rptr: RPtr, schema_int: i32, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let metadatum = metadatum_rptr.typed_ref::<TransactionMetadatum>()?;
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::decode_metadatum_to_json_str(metadatum, schema).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decode_plutus_datum_to_json_str(datum_rptr: RPtr, schema_int: i32, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let datum = datum_rptr.typed_ref::<PlutusData>()?;
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::decode_plutus_datum_to_json_str(datum, schema).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn decrypt_with_password(password_str: CharPtr, data_str: CharPtr, result: &mut CharPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let password: &str = password_str.into_str();
    let data: &str = data_str.into_str();
    let result = cardano_serialization_lib::decrypt_with_password(password, data).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_arbitrary_bytes_as_metadatum(bytes_data: *const u8, bytes_len: usize, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let bytes = from_raw_parts(bytes_data, bytes_len);
    let result = cardano_serialization_lib::encode_arbitrary_bytes_as_metadatum(bytes);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_metadatum(json_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json : String = json_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::encode_json_str_to_metadatum(json, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_native_script(json_str: CharPtr, self_xpub_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let self_xpub: &str = self_xpub_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::encode_json_str_to_native_script(json, self_xpub, schema).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn encode_json_str_to_plutus_datum(json_str: CharPtr, schema_int: i32, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let json: &str = json_str.into_str();
    let schema = schema_int.to_enum()?;
    let result = cardano_serialization_lib::encode_json_str_to_plutus_datum(json, schema).into_result()?;
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
    let result = cardano_serialization_lib::encrypt_with_password(password, salt, nonce, data).into_result()?;
    Ok::<CharPtr, String>(result.into_cstr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn get_deposit(txbody_rptr: RPtr, pool_deposit_rptr: RPtr, key_deposit_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let txbody = txbody_rptr.typed_ref::<TransactionBody>()?;
    let pool_deposit = pool_deposit_rptr.typed_ref::<BigNum>()?;
    let key_deposit = key_deposit_rptr.typed_ref::<BigNum>()?;
    let result = cardano_serialization_lib::get_deposit(txbody, pool_deposit, key_deposit).into_result()?;
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
    let result = cardano_serialization_lib::get_implicit_input(txbody, pool_deposit, key_deposit).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_auxiliary_data(auxiliary_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let auxiliary_data = auxiliary_data_rptr.typed_ref::<AuxiliaryData>()?;
    let result = cardano_serialization_lib::hash_auxiliary_data(auxiliary_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_plutus_data(plutus_data_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let plutus_data = plutus_data_rptr.typed_ref::<PlutusData>()?;
    let result = cardano_serialization_lib::hash_plutus_data(plutus_data);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn hash_script_data(redeemers_rptr: RPtr, cost_models_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let redeemers = redeemers_rptr.typed_ref::<Redeemers>()?;
    let cost_models = cost_models_rptr.typed_ref::<Costmdls>()?;
    let result = cardano_serialization_lib::hash_script_data(redeemers, cost_models, None);
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
    let result = cardano_serialization_lib::hash_script_data(redeemers, cost_models, Some(datums));
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}



#[no_mangle]
pub unsafe extern "C" fn hash_transaction(tx_body_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body = tx_body_rptr.typed_ref::<TransactionBody>()?;
    let result = cardano_serialization_lib::hash_transaction(tx_body);
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
    let result = cardano_serialization_lib::make_daedalus_bootstrap_witness(tx_body_hash, addr, key);
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
    let result = cardano_serialization_lib::make_icarus_bootstrap_witness(tx_body_hash, addr, key);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn make_vkey_witness(tx_body_hash_rptr: RPtr, sk_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx_body_hash = tx_body_hash_rptr.typed_ref::<TransactionHash>()?;
    let sk = sk_rptr.typed_ref::<PrivateKey>()?;
    let result = cardano_serialization_lib::make_vkey_witness(tx_body_hash, sk);
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_ada_for_output(output_rptr: RPtr, data_cost_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let output = output_rptr.typed_ref::<TransactionOutput>()?;
    let data_cost = data_cost_rptr.typed_ref::<DataCost>()?;
    let result = cardano_serialization_lib::min_ada_for_output(output, data_cost).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_fee(tx_rptr: RPtr, linear_fee_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx = tx_rptr.typed_ref::<Transaction>()?;
    let linear_fee = linear_fee_rptr.typed_ref::<LinearFee>()?;
    let result = cardano_serialization_lib::min_fee(tx, linear_fee).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


#[no_mangle]
pub unsafe extern "C" fn min_script_fee(tx_rptr: RPtr, ex_unit_prices_rptr: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| { 
    let tx = tx_rptr.typed_ref::<Transaction>()?;
    let ex_unit_prices = ex_unit_prices_rptr.typed_ref::<ExUnitPrices>()?;
    let result = cardano_serialization_lib::min_script_fee(tx, ex_unit_prices).into_result()?;
    Ok::<RPtr, String>(result.rptr())
  })
  .response(result,  error)
}


