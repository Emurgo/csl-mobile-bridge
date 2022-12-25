use cardano_serialization_lib::plutus::PlutusDataKind;
use cardano_serialization_lib::MIRKind;
use cardano_serialization_lib::metadata::TransactionMetadatumKind;
use cardano_serialization_lib::metadata::MetadataJsonSchema;
use cardano_serialization_lib::utils::ScriptSchema;
use cardano_serialization_lib::plutus::PlutusDatumSchema;
use cardano_serialization_lib::ScriptHashNamespace;
use cardano_serialization_lib::address::StakeCredKind;
use cardano_serialization_lib::plutus::LanguageKind;
use cardano_serialization_lib::CertificateKind;
use cardano_serialization_lib::NativeScriptKind;
use cardano_serialization_lib::RelayKind;
use cardano_serialization_lib::plutus::RedeemerTagKind;
use cardano_serialization_lib::MIRPot;
use cardano_serialization_lib::NetworkIdKind;
use cardano_serialization_lib::tx_builder::CoinSelectionStrategyCIP2;

use crate::panic::Result;

pub trait ToPrimitive {
    fn to_i32(&self) -> i32;
}

pub trait ToEnum<T> {
    fn to_enum(&self) -> Result<T>;
}
impl ToPrimitive for NetworkIdKind {
    fn to_i32(&self) -> i32 {
        match self {
            NetworkIdKind::Testnet => 0,
            NetworkIdKind::Mainnet => 1,
        }
    }
}

impl ToEnum<NetworkIdKind> for i32 {
    fn to_enum(&self) -> Result<NetworkIdKind> {
        match self {
            0 => Ok(NetworkIdKind::Testnet),
            1 => Ok(NetworkIdKind::Mainnet),
            _ => Err("Invalid value for NetworkIdKind".into()),
        }
    }
}

impl ToPrimitive for ScriptHashNamespace {
    fn to_i32(&self) -> i32 {
        match self {
            ScriptHashNamespace::NativeScript => 0,
            ScriptHashNamespace::PlutusScript => 1,
            ScriptHashNamespace::PlutusScriptV2 => 2,
        }
    }
}

impl ToEnum<ScriptHashNamespace> for i32 {
    fn to_enum(&self) -> Result<ScriptHashNamespace> {
        match self {
            0 => Ok(ScriptHashNamespace::NativeScript),
            1 => Ok(ScriptHashNamespace::PlutusScript),
            2 => Ok(ScriptHashNamespace::PlutusScriptV2),
            _ => Err("Invalid value for ScriptHashNamespace".into()),
        }
    }
}

impl ToPrimitive for PlutusDataKind {
    fn to_i32(&self) -> i32 {
        match self {
            PlutusDataKind::ConstrPlutusData => 0,
            PlutusDataKind::Map => 1,
            PlutusDataKind::List => 2,
            PlutusDataKind::Integer => 3,
            PlutusDataKind::Bytes => 4,
        }
    }
}

impl ToEnum<PlutusDataKind> for i32 {
    fn to_enum(&self) -> Result<PlutusDataKind> {
        match self {
            0 => Ok(PlutusDataKind::ConstrPlutusData),
            1 => Ok(PlutusDataKind::Map),
            2 => Ok(PlutusDataKind::List),
            3 => Ok(PlutusDataKind::Integer),
            4 => Ok(PlutusDataKind::Bytes),
            _ => Err("Invalid value for PlutusDataKind".into()),
        }
    }
}

impl ToPrimitive for PlutusDatumSchema {
    fn to_i32(&self) -> i32 {
        match self {
            PlutusDatumSchema::BasicConversions => 0,
            PlutusDatumSchema::DetailedSchema => 1,
        }
    }
}

impl ToEnum<PlutusDatumSchema> for i32 {
    fn to_enum(&self) -> Result<PlutusDatumSchema> {
        match self {
            0 => Ok(PlutusDatumSchema::BasicConversions),
            1 => Ok(PlutusDatumSchema::DetailedSchema),
            _ => Err("Invalid value for PlutusDatumSchema".into()),
        }
    }
}

impl ToPrimitive for NativeScriptKind {
    fn to_i32(&self) -> i32 {
        match self {
            NativeScriptKind::ScriptPubkey => 0,
            NativeScriptKind::ScriptAll => 1,
            NativeScriptKind::ScriptAny => 2,
            NativeScriptKind::ScriptNOfK => 3,
            NativeScriptKind::TimelockStart => 4,
            NativeScriptKind::TimelockExpiry => 5,
        }
    }
}

impl ToEnum<NativeScriptKind> for i32 {
    fn to_enum(&self) -> Result<NativeScriptKind> {
        match self {
            0 => Ok(NativeScriptKind::ScriptPubkey),
            1 => Ok(NativeScriptKind::ScriptAll),
            2 => Ok(NativeScriptKind::ScriptAny),
            3 => Ok(NativeScriptKind::ScriptNOfK),
            4 => Ok(NativeScriptKind::TimelockStart),
            5 => Ok(NativeScriptKind::TimelockExpiry),
            _ => Err("Invalid value for NativeScriptKind".into()),
        }
    }
}

impl ToPrimitive for MetadataJsonSchema {
    fn to_i32(&self) -> i32 {
        match self {
            MetadataJsonSchema::NoConversions => 0,
            MetadataJsonSchema::BasicConversions => 1,
            MetadataJsonSchema::DetailedSchema => 2,
        }
    }
}

impl ToEnum<MetadataJsonSchema> for i32 {
    fn to_enum(&self) -> Result<MetadataJsonSchema> {
        match self {
            0 => Ok(MetadataJsonSchema::NoConversions),
            1 => Ok(MetadataJsonSchema::BasicConversions),
            2 => Ok(MetadataJsonSchema::DetailedSchema),
            _ => Err("Invalid value for MetadataJsonSchema".into()),
        }
    }
}

impl ToPrimitive for CertificateKind {
    fn to_i32(&self) -> i32 {
        match self {
            CertificateKind::StakeRegistration => 0,
            CertificateKind::StakeDeregistration => 1,
            CertificateKind::StakeDelegation => 2,
            CertificateKind::PoolRegistration => 3,
            CertificateKind::PoolRetirement => 4,
            CertificateKind::GenesisKeyDelegation => 5,
            CertificateKind::MoveInstantaneousRewardsCert => 6,
        }
    }
}

impl ToEnum<CertificateKind> for i32 {
    fn to_enum(&self) -> Result<CertificateKind> {
        match self {
            0 => Ok(CertificateKind::StakeRegistration),
            1 => Ok(CertificateKind::StakeDeregistration),
            2 => Ok(CertificateKind::StakeDelegation),
            3 => Ok(CertificateKind::PoolRegistration),
            4 => Ok(CertificateKind::PoolRetirement),
            5 => Ok(CertificateKind::GenesisKeyDelegation),
            6 => Ok(CertificateKind::MoveInstantaneousRewardsCert),
            _ => Err("Invalid value for CertificateKind".into()),
        }
    }
}

impl ToPrimitive for RelayKind {
    fn to_i32(&self) -> i32 {
        match self {
            RelayKind::SingleHostAddr => 0,
            RelayKind::SingleHostName => 1,
            RelayKind::MultiHostName => 2,
        }
    }
}

impl ToEnum<RelayKind> for i32 {
    fn to_enum(&self) -> Result<RelayKind> {
        match self {
            0 => Ok(RelayKind::SingleHostAddr),
            1 => Ok(RelayKind::SingleHostName),
            2 => Ok(RelayKind::MultiHostName),
            _ => Err("Invalid value for RelayKind".into()),
        }
    }
}

impl ToPrimitive for ScriptSchema {
    fn to_i32(&self) -> i32 {
        match self {
            ScriptSchema::Wallet => 0,
            ScriptSchema::Node => 1,
        }
    }
}

impl ToEnum<ScriptSchema> for i32 {
    fn to_enum(&self) -> Result<ScriptSchema> {
        match self {
            0 => Ok(ScriptSchema::Wallet),
            1 => Ok(ScriptSchema::Node),
            _ => Err("Invalid value for ScriptSchema".into()),
        }
    }
}

impl ToPrimitive for StakeCredKind {
    fn to_i32(&self) -> i32 {
        match self {
            StakeCredKind::Key => 0,
            StakeCredKind::Script => 1,
        }
    }
}

impl ToEnum<StakeCredKind> for i32 {
    fn to_enum(&self) -> Result<StakeCredKind> {
        match self {
            0 => Ok(StakeCredKind::Key),
            1 => Ok(StakeCredKind::Script),
            _ => Err("Invalid value for StakeCredKind".into()),
        }
    }
}

impl ToPrimitive for TransactionMetadatumKind {
    fn to_i32(&self) -> i32 {
        match self {
            TransactionMetadatumKind::MetadataMap => 0,
            TransactionMetadatumKind::MetadataList => 1,
            TransactionMetadatumKind::Int => 2,
            TransactionMetadatumKind::Bytes => 3,
            TransactionMetadatumKind::Text => 4,
        }
    }
}

impl ToEnum<TransactionMetadatumKind> for i32 {
    fn to_enum(&self) -> Result<TransactionMetadatumKind> {
        match self {
            0 => Ok(TransactionMetadatumKind::MetadataMap),
            1 => Ok(TransactionMetadatumKind::MetadataList),
            2 => Ok(TransactionMetadatumKind::Int),
            3 => Ok(TransactionMetadatumKind::Bytes),
            4 => Ok(TransactionMetadatumKind::Text),
            _ => Err("Invalid value for TransactionMetadatumKind".into()),
        }
    }
}

impl ToPrimitive for LanguageKind {
    fn to_i32(&self) -> i32 {
        match self {
            LanguageKind::PlutusV1 => 0,
            LanguageKind::PlutusV2 => 1,
        }
    }
}

impl ToEnum<LanguageKind> for i32 {
    fn to_enum(&self) -> Result<LanguageKind> {
        match self {
            0 => Ok(LanguageKind::PlutusV1),
            1 => Ok(LanguageKind::PlutusV2),
            _ => Err("Invalid value for LanguageKind".into()),
        }
    }
}

impl ToPrimitive for MIRPot {
    fn to_i32(&self) -> i32 {
        match self {
            MIRPot::Reserves => 0,
            MIRPot::Treasury => 1,
        }
    }
}

impl ToEnum<MIRPot> for i32 {
    fn to_enum(&self) -> Result<MIRPot> {
        match self {
            0 => Ok(MIRPot::Reserves),
            1 => Ok(MIRPot::Treasury),
            _ => Err("Invalid value for MIRPot".into()),
        }
    }
}

impl ToPrimitive for MIRKind {
    fn to_i32(&self) -> i32 {
        match self {
            MIRKind::ToOtherPot => 0,
            MIRKind::ToStakeCredentials => 1,
        }
    }
}

impl ToEnum<MIRKind> for i32 {
    fn to_enum(&self) -> Result<MIRKind> {
        match self {
            0 => Ok(MIRKind::ToOtherPot),
            1 => Ok(MIRKind::ToStakeCredentials),
            _ => Err("Invalid value for MIRKind".into()),
        }
    }
}

impl ToPrimitive for CoinSelectionStrategyCIP2 {
    fn to_i32(&self) -> i32 {
        match self {
            CoinSelectionStrategyCIP2::LargestFirst => 0,
            CoinSelectionStrategyCIP2::RandomImprove => 1,
            CoinSelectionStrategyCIP2::LargestFirstMultiAsset => 2,
            CoinSelectionStrategyCIP2::RandomImproveMultiAsset => 3,
        }
    }
}

impl ToEnum<CoinSelectionStrategyCIP2> for i32 {
    fn to_enum(&self) -> Result<CoinSelectionStrategyCIP2> {
        match self {
            0 => Ok(CoinSelectionStrategyCIP2::LargestFirst),
            1 => Ok(CoinSelectionStrategyCIP2::RandomImprove),
            2 => Ok(CoinSelectionStrategyCIP2::LargestFirstMultiAsset),
            3 => Ok(CoinSelectionStrategyCIP2::RandomImproveMultiAsset),
            _ => Err("Invalid value for CoinSelectionStrategyCIP2".into()),
        }
    }
}

impl ToPrimitive for RedeemerTagKind {
    fn to_i32(&self) -> i32 {
        match self {
            RedeemerTagKind::Spend => 0,
            RedeemerTagKind::Mint => 1,
            RedeemerTagKind::Cert => 2,
            RedeemerTagKind::Reward => 3,
        }
    }
}

impl ToEnum<RedeemerTagKind> for i32 {
    fn to_enum(&self) -> Result<RedeemerTagKind> {
        match self {
            0 => Ok(RedeemerTagKind::Spend),
            1 => Ok(RedeemerTagKind::Mint),
            2 => Ok(RedeemerTagKind::Cert),
            3 => Ok(RedeemerTagKind::Reward),
            _ => Err("Invalid value for RedeemerTagKind".into()),
        }
    }
}

