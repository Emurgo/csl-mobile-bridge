use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::AssetName;
use cardano_serialization_lib::AssetNames;
use cardano_serialization_lib::Assets;
use cardano_serialization_lib::AuxiliaryDataSet;
use cardano_serialization_lib::Block;
use cardano_serialization_lib::Certificate;
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
use cardano_serialization_lib::MIRToStakeCredentials;
use cardano_serialization_lib::Mint;
use cardano_serialization_lib::MintAssets;
use cardano_serialization_lib::MintsAssets;
use cardano_serialization_lib::MoveInstantaneousReward;
use cardano_serialization_lib::MoveInstantaneousRewardsCert;
use cardano_serialization_lib::MultiAsset;
use cardano_serialization_lib::MultiHostName;
use cardano_serialization_lib::NativeScript;
use cardano_serialization_lib::NativeScripts;
use cardano_serialization_lib::NetworkId;
use cardano_serialization_lib::OperationalCert;
use cardano_serialization_lib::PoolMetadata;
use cardano_serialization_lib::PoolParams;
use cardano_serialization_lib::PoolRegistration;
use cardano_serialization_lib::PoolRetirement;
use cardano_serialization_lib::ProposedProtocolParameterUpdates;
use cardano_serialization_lib::ProtocolParamUpdate;
use cardano_serialization_lib::ProtocolVersion;
use cardano_serialization_lib::Relay;
use cardano_serialization_lib::Relays;
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::ScriptAll;
use cardano_serialization_lib::ScriptAny;
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
use cardano_serialization_lib::metadata::MetadataList;
use cardano_serialization_lib::metadata::MetadataMap;
use cardano_serialization_lib::metadata::TransactionMetadatum;
use cardano_serialization_lib::metadata::TransactionMetadatumLabels;
use cardano_serialization_lib::output_builder::TransactionOutputAmountBuilder;
use cardano_serialization_lib::output_builder::TransactionOutputBuilder;
use cardano_serialization_lib::plutus::ConstrPlutusData;
use cardano_serialization_lib::plutus::CostModel;
use cardano_serialization_lib::plutus::Costmdls;
use cardano_serialization_lib::plutus::ExUnitPrices;
use cardano_serialization_lib::plutus::ExUnits;
use cardano_serialization_lib::plutus::Language;
use cardano_serialization_lib::plutus::Languages;
use cardano_serialization_lib::plutus::PlutusData;
use cardano_serialization_lib::plutus::PlutusList;
use cardano_serialization_lib::plutus::PlutusMap;
use cardano_serialization_lib::plutus::PlutusScript;
use cardano_serialization_lib::plutus::PlutusScripts;
use cardano_serialization_lib::plutus::Redeemer;
use cardano_serialization_lib::plutus::RedeemerTag;
use cardano_serialization_lib::plutus::Redeemers;
use cardano_serialization_lib::plutus::Strings;
use cardano_serialization_lib::protocol_types::fixed_tx::FixedTransaction;
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
use cardano_serialization_lib::utils::TransactionUnspentOutput;
use cardano_serialization_lib::utils::TransactionUnspentOutputs;
use cardano_serialization_lib::utils::Value;
impl RPtrRepresentable for Address {}
impl RPtrRepresentable for AssetName {}
impl RPtrRepresentable for AssetNames {}
impl RPtrRepresentable for Assets {}
impl RPtrRepresentable for AuxiliaryData {}
impl RPtrRepresentable for AuxiliaryDataHash {}
impl RPtrRepresentable for AuxiliaryDataSet {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for BigInt {}
impl RPtrRepresentable for BigNum {}
impl RPtrRepresentable for Bip32PrivateKey {}
impl RPtrRepresentable for Bip32PublicKey {}
impl RPtrRepresentable for Block {}
impl RPtrRepresentable for BlockHash {}
impl RPtrRepresentable for BootstrapWitness {}
impl RPtrRepresentable for BootstrapWitnesses {}
impl RPtrRepresentable for ByronAddress {}
impl RPtrRepresentable for Certificate {}
impl RPtrRepresentable for Certificates {}
impl RPtrRepresentable for ConstrPlutusData {}
impl RPtrRepresentable for CostModel {}
impl RPtrRepresentable for Costmdls {}
impl RPtrRepresentable for DNSRecordAorAAAA {}
impl RPtrRepresentable for DNSRecordSRV {}
impl RPtrRepresentable for DataCost {}
impl RPtrRepresentable for DataHash {}
impl RPtrRepresentable for DatumSource {}
impl RPtrRepresentable for Ed25519KeyHash {}
impl RPtrRepresentable for Ed25519KeyHashes {}
impl RPtrRepresentable for Ed25519Signature {}
impl RPtrRepresentable for EnterpriseAddress {}
impl RPtrRepresentable for ExUnitPrices {}
impl RPtrRepresentable for ExUnits {}
impl RPtrRepresentable for FixedTransaction {}
impl RPtrRepresentable for GeneralTransactionMetadata {}
impl RPtrRepresentable for GenesisDelegateHash {}
impl RPtrRepresentable for GenesisHash {}
impl RPtrRepresentable for GenesisHashes {}
impl RPtrRepresentable for GenesisKeyDelegation {}
impl RPtrRepresentable for Header {}
impl RPtrRepresentable for HeaderBody {}
impl RPtrRepresentable for InputWithScriptWitness {}
impl RPtrRepresentable for InputsWithScriptWitness {}
impl RPtrRepresentable for Int {}
impl RPtrRepresentable for Ipv4 {}
impl RPtrRepresentable for Ipv6 {}
impl RPtrRepresentable for KESSignature {}
impl RPtrRepresentable for KESVKey {}
impl RPtrRepresentable for Language {}
impl RPtrRepresentable for Languages {}
impl RPtrRepresentable for LegacyDaedalusPrivateKey {}
impl RPtrRepresentable for LinearFee {}
impl RPtrRepresentable for MIRToStakeCredentials {}
impl RPtrRepresentable for MetadataList {}
impl RPtrRepresentable for MetadataMap {}
impl RPtrRepresentable for Mint {}
impl RPtrRepresentable for MintAssets {}
impl RPtrRepresentable for MintBuilder {}
impl RPtrRepresentable for MintWitness {}
impl RPtrRepresentable for MintsAssets {}
impl RPtrRepresentable for MoveInstantaneousReward {}
impl RPtrRepresentable for MoveInstantaneousRewardsCert {}
impl RPtrRepresentable for MultiAsset {}
impl RPtrRepresentable for MultiHostName {}
impl RPtrRepresentable for NativeScript {}
impl RPtrRepresentable for NativeScripts {}
impl RPtrRepresentable for NetworkId {}
impl RPtrRepresentable for NetworkInfo {}
impl RPtrRepresentable for Nonce {}
impl RPtrRepresentable for OperationalCert {}
impl RPtrRepresentable for PlutusData {}
impl RPtrRepresentable for PlutusList {}
impl RPtrRepresentable for PlutusMap {}
impl RPtrRepresentable for PlutusScript {}
impl RPtrRepresentable for PlutusScriptSource {}
impl RPtrRepresentable for PlutusScripts {}
impl RPtrRepresentable for PlutusWitness {}
impl RPtrRepresentable for PlutusWitnesses {}
impl RPtrRepresentable for Pointer {}
impl RPtrRepresentable for PointerAddress {}
impl RPtrRepresentable for PoolMetadata {}
impl RPtrRepresentable for PoolMetadataHash {}
impl RPtrRepresentable for PoolParams {}
impl RPtrRepresentable for PoolRegistration {}
impl RPtrRepresentable for PoolRetirement {}
impl RPtrRepresentable for PrivateKey {}
impl RPtrRepresentable for ProposedProtocolParameterUpdates {}
impl RPtrRepresentable for ProtocolParamUpdate {}
impl RPtrRepresentable for ProtocolVersion {}
impl RPtrRepresentable for PublicKey {}
impl RPtrRepresentable for PublicKeys {}
impl RPtrRepresentable for Redeemer {}
impl RPtrRepresentable for RedeemerTag {}
impl RPtrRepresentable for Redeemers {}
impl RPtrRepresentable for Relay {}
impl RPtrRepresentable for Relays {}
impl RPtrRepresentable for RewardAddress {}
impl RPtrRepresentable for RewardAddresses {}
impl RPtrRepresentable for ScriptAll {}
impl RPtrRepresentable for ScriptAny {}
impl RPtrRepresentable for ScriptDataHash {}
impl RPtrRepresentable for ScriptHash {}
impl RPtrRepresentable for ScriptHashes {}
impl RPtrRepresentable for ScriptNOfK {}
impl RPtrRepresentable for ScriptPubkey {}
impl RPtrRepresentable for ScriptRef {}
impl RPtrRepresentable for SingleHostAddr {}
impl RPtrRepresentable for SingleHostName {}
impl RPtrRepresentable for StakeCredential {}
impl RPtrRepresentable for StakeCredentials {}
impl RPtrRepresentable for StakeDelegation {}
impl RPtrRepresentable for StakeDeregistration {}
impl RPtrRepresentable for StakeRegistration {}
impl RPtrRepresentable for Strings {}
impl RPtrRepresentable for TimelockExpiry {}
impl RPtrRepresentable for TimelockStart {}
impl RPtrRepresentable for Transaction {}
impl RPtrRepresentable for TransactionBatch {}
impl RPtrRepresentable for TransactionBatchList {}
impl RPtrRepresentable for TransactionBodies {}
impl RPtrRepresentable for TransactionBody {}
impl RPtrRepresentable for TransactionBuilder {}
impl RPtrRepresentable for TransactionBuilderConfig {}
impl RPtrRepresentable for TransactionBuilderConfigBuilder {}
impl RPtrRepresentable for TransactionHash {}
impl RPtrRepresentable for TransactionInput {}
impl RPtrRepresentable for TransactionInputs {}
impl RPtrRepresentable for TransactionMetadatum {}
impl RPtrRepresentable for TransactionMetadatumLabels {}
impl RPtrRepresentable for TransactionOutput {}
impl RPtrRepresentable for TransactionOutputAmountBuilder {}
impl RPtrRepresentable for TransactionOutputBuilder {}
impl RPtrRepresentable for TransactionOutputs {}
impl RPtrRepresentable for TransactionUnspentOutput {}
impl RPtrRepresentable for TransactionUnspentOutputs {}
impl RPtrRepresentable for TransactionWitnessSet {}
impl RPtrRepresentable for TransactionWitnessSets {}
impl RPtrRepresentable for TxBuilderConstants {}
impl RPtrRepresentable for TxInputsBuilder {}
impl RPtrRepresentable for URL {}
impl RPtrRepresentable for UnitInterval {}
impl RPtrRepresentable for Update {}
impl RPtrRepresentable for VRFCert {}
impl RPtrRepresentable for VRFKeyHash {}
impl RPtrRepresentable for VRFVKey {}
impl RPtrRepresentable for Value {}
impl RPtrRepresentable for Vkey {}
impl RPtrRepresentable for Vkeys {}
impl RPtrRepresentable for Vkeywitness {}
impl RPtrRepresentable for Vkeywitnesses {}
impl RPtrRepresentable for Withdrawals {}
