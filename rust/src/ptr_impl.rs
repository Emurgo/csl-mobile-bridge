use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::address::*;
use cardano_serialization_lib::crypto::*;
use cardano_serialization_lib::utils::*;
use cardano_serialization_lib::fees::*;
use cardano_serialization_lib::tx_builder::*;
use cardano_serialization_lib::metadata::*;
use cardano_serialization_lib::*;

impl RPtrRepresentable for Address {}
impl RPtrRepresentable for AssetName {}
impl RPtrRepresentable for AssetNames {}
impl RPtrRepresentable for Assets {}
impl RPtrRepresentable for AuxiliaryData {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for BigNum {}
impl RPtrRepresentable for Bip32PrivateKey {}
impl RPtrRepresentable for Bip32PublicKey {}
impl RPtrRepresentable for BootstrapWitness {}
impl RPtrRepresentable for BootstrapWitnesses {}
impl RPtrRepresentable for ByronAddress {}
impl RPtrRepresentable for Certificate {}
impl RPtrRepresentable for Certificates {}
impl RPtrRepresentable for Ed25519Signature {}
impl RPtrRepresentable for Ed25519KeyHash {}
impl RPtrRepresentable for EnterpriseAddress {}
impl RPtrRepresentable for GeneralTransactionMetadata {}
impl RPtrRepresentable for Int {}
impl RPtrRepresentable for LinearFee {}
impl RPtrRepresentable for MetadataList {}
impl RPtrRepresentable for MetadataMap {}
impl RPtrRepresentable for MultiAsset {}
impl RPtrRepresentable for PrivateKey {}
impl RPtrRepresentable for PublicKey {}
impl RPtrRepresentable for RewardAddress {}
impl RPtrRepresentable for RewardAddresses {}
impl RPtrRepresentable for ScriptHash {}
impl RPtrRepresentable for ScriptHashes {}
impl RPtrRepresentable for StakeCredential {}
impl RPtrRepresentable for StakeDelegation {}
impl RPtrRepresentable for StakeDeregistration {}
impl RPtrRepresentable for StakeRegistration {}
impl RPtrRepresentable for Transaction {}
impl RPtrRepresentable for TransactionBody {}
impl RPtrRepresentable for TransactionBuilder {}
impl RPtrRepresentable for TransactionInput {}
impl RPtrRepresentable for TransactionInputs {}
impl RPtrRepresentable for TransactionMetadatum {}
impl RPtrRepresentable for TransactionMetadatumLabels {}
impl RPtrRepresentable for TransactionOutput {}
impl RPtrRepresentable for TransactionOutputs {}
impl RPtrRepresentable for TransactionWitnessSet {}
impl RPtrRepresentable for TransactionHash {}
impl RPtrRepresentable for UnitInterval {}
impl RPtrRepresentable for Value {}
impl RPtrRepresentable for Vkey {}
impl RPtrRepresentable for Vkeywitness {}
impl RPtrRepresentable for Vkeywitnesses {}
impl RPtrRepresentable for Withdrawals {}
