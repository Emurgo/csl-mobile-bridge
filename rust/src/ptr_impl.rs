use crate::ptr::RPtrRepresentable;
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
use cardano_serialization_lib::Certificate;
use cardano_serialization_lib::Certificates;
use cardano_serialization_lib::CertificatesBuilder;
use cardano_serialization_lib::Committee;
use cardano_serialization_lib::CommitteeColdResign;
use cardano_serialization_lib::CommitteeHotAuth;
use cardano_serialization_lib::Constitution;
use cardano_serialization_lib::ConstrPlutusData;
use cardano_serialization_lib::CostModel;
use cardano_serialization_lib::Costmdls;
use cardano_serialization_lib::Credential;
use cardano_serialization_lib::Credentials;
use cardano_serialization_lib::DNSRecordAorAAAA;
use cardano_serialization_lib::DNSRecordSRV;
use cardano_serialization_lib::DRep;
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
use cardano_serialization_lib::HardForkInitiationAction;
use cardano_serialization_lib::Header;
use cardano_serialization_lib::HeaderBody;
use cardano_serialization_lib::InfoAction;
use cardano_serialization_lib::InputWithScriptWitness;
use cardano_serialization_lib::InputsWithScriptWitness;
use cardano_serialization_lib::Int;
use cardano_serialization_lib::Ipv4;
use cardano_serialization_lib::Ipv6;
use cardano_serialization_lib::KESSignature;
use cardano_serialization_lib::KESVKey;
use cardano_serialization_lib::Language;
use cardano_serialization_lib::Languages;
use cardano_serialization_lib::LegacyDaedalusPrivateKey;
use cardano_serialization_lib::LinearFee;
use cardano_serialization_lib::MIRToStakeCredentials;
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
use cardano_serialization_lib::NativeScriptSource;
use cardano_serialization_lib::NativeScripts;
use cardano_serialization_lib::NetworkId;
use cardano_serialization_lib::NetworkInfo;
use cardano_serialization_lib::NewConstitutionAction;
use cardano_serialization_lib::NoConfidenceAction;
use cardano_serialization_lib::Nonce;
use cardano_serialization_lib::OperationalCert;
use cardano_serialization_lib::OutputDatum;
use cardano_serialization_lib::ParameterChangeAction;
use cardano_serialization_lib::PlutusData;
use cardano_serialization_lib::PlutusList;
use cardano_serialization_lib::PlutusMap;
use cardano_serialization_lib::PlutusScript;
use cardano_serialization_lib::PlutusScriptSource;
use cardano_serialization_lib::PlutusScripts;
use cardano_serialization_lib::PlutusWitness;
use cardano_serialization_lib::PlutusWitnesses;
use cardano_serialization_lib::Pointer;
use cardano_serialization_lib::PointerAddress;
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
use cardano_serialization_lib::Redeemers;
use cardano_serialization_lib::Relay;
use cardano_serialization_lib::Relays;
use cardano_serialization_lib::RewardAddress;
use cardano_serialization_lib::RewardAddresses;
use cardano_serialization_lib::ScriptAll;
use cardano_serialization_lib::ScriptAny;
use cardano_serialization_lib::ScriptDataHash;
use cardano_serialization_lib::ScriptHash;
use cardano_serialization_lib::ScriptHashes;
use cardano_serialization_lib::ScriptNOfK;
use cardano_serialization_lib::ScriptPubkey;
use cardano_serialization_lib::ScriptRef;
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
use cardano_serialization_lib::VoteRegistrationAndDelegation;
use cardano_serialization_lib::Voter;
use cardano_serialization_lib::Voters;
use cardano_serialization_lib::VotingBuilder;
use cardano_serialization_lib::VotingProcedure;
use cardano_serialization_lib::VotingProcedures;
use cardano_serialization_lib::VotingProposal;
use cardano_serialization_lib::VotingProposalBuilder;
use cardano_serialization_lib::VotingProposals;
use cardano_serialization_lib::Withdrawals;
use cardano_serialization_lib::WithdrawalsBuilder;
impl RPtrRepresentable for Address {}
impl RPtrRepresentable for Anchor {}
impl RPtrRepresentable for AnchorDataHash {}
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
impl RPtrRepresentable for CertificatesBuilder {}
impl RPtrRepresentable for Committee {}
impl RPtrRepresentable for CommitteeColdResign {}
impl RPtrRepresentable for CommitteeHotAuth {}
impl RPtrRepresentable for Constitution {}
impl RPtrRepresentable for ConstrPlutusData {}
impl RPtrRepresentable for CostModel {}
impl RPtrRepresentable for Costmdls {}
impl RPtrRepresentable for Credential {}
impl RPtrRepresentable for Credentials {}
impl RPtrRepresentable for DNSRecordAorAAAA {}
impl RPtrRepresentable for DNSRecordSRV {}
impl RPtrRepresentable for DRep {}
impl RPtrRepresentable for DataCost {}
impl RPtrRepresentable for DataHash {}
impl RPtrRepresentable for DatumSource {}
impl RPtrRepresentable for DrepDeregistration {}
impl RPtrRepresentable for DrepRegistration {}
impl RPtrRepresentable for DrepUpdate {}
impl RPtrRepresentable for DrepVotingThresholds {}
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
impl RPtrRepresentable for GovernanceAction {}
impl RPtrRepresentable for GovernanceActionId {}
impl RPtrRepresentable for GovernanceActionIds {}
impl RPtrRepresentable for HardForkInitiationAction {}
impl RPtrRepresentable for Header {}
impl RPtrRepresentable for HeaderBody {}
impl RPtrRepresentable for InfoAction {}
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
impl RPtrRepresentable for NativeScriptSource {}
impl RPtrRepresentable for NativeScripts {}
impl RPtrRepresentable for NetworkId {}
impl RPtrRepresentable for NetworkInfo {}
impl RPtrRepresentable for NewConstitutionAction {}
impl RPtrRepresentable for NoConfidenceAction {}
impl RPtrRepresentable for Nonce {}
impl RPtrRepresentable for OperationalCert {}
impl RPtrRepresentable for OutputDatum {}
impl RPtrRepresentable for ParameterChangeAction {}
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
impl RPtrRepresentable for PoolVotingThresholds {}
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
impl RPtrRepresentable for StakeAndVoteDelegation {}
impl RPtrRepresentable for StakeDelegation {}
impl RPtrRepresentable for StakeDeregistration {}
impl RPtrRepresentable for StakeRegistration {}
impl RPtrRepresentable for StakeRegistrationAndDelegation {}
impl RPtrRepresentable for StakeVoteRegistrationAndDelegation {}
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
impl RPtrRepresentable for TreasuryWithdrawals {}
impl RPtrRepresentable for TreasuryWithdrawalsAction {}
impl RPtrRepresentable for TxBuilderConstants {}
impl RPtrRepresentable for TxInputsBuilder {}
impl RPtrRepresentable for URL {}
impl RPtrRepresentable for UnitInterval {}
impl RPtrRepresentable for Update {}
impl RPtrRepresentable for UpdateCommitteeAction {}
impl RPtrRepresentable for VRFCert {}
impl RPtrRepresentable for VRFKeyHash {}
impl RPtrRepresentable for VRFVKey {}
impl RPtrRepresentable for Value {}
impl RPtrRepresentable for Vkey {}
impl RPtrRepresentable for Vkeys {}
impl RPtrRepresentable for Vkeywitness {}
impl RPtrRepresentable for Vkeywitnesses {}
impl RPtrRepresentable for VoteDelegation {}
impl RPtrRepresentable for VoteRegistrationAndDelegation {}
impl RPtrRepresentable for Voter {}
impl RPtrRepresentable for Voters {}
impl RPtrRepresentable for VotingBuilder {}
impl RPtrRepresentable for VotingProcedure {}
impl RPtrRepresentable for VotingProcedures {}
impl RPtrRepresentable for VotingProposal {}
impl RPtrRepresentable for VotingProposalBuilder {}
impl RPtrRepresentable for VotingProposals {}
impl RPtrRepresentable for Withdrawals {}
impl RPtrRepresentable for WithdrawalsBuilder {}
