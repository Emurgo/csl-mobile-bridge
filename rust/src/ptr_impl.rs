use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::address::*;
use cardano_serialization_lib::crypto::*;
use cardano_serialization_lib::utils::*;
use cardano_serialization_lib::fees::*;
use cardano_serialization_lib::*;

impl RPtrRepresentable for Address {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for BigNum {}
impl RPtrRepresentable for Bip32PrivateKey {}
impl RPtrRepresentable for Bip32PublicKey {}
impl RPtrRepresentable for ByronAddress {}
impl RPtrRepresentable for Ed25519KeyHash {}
impl RPtrRepresentable for LinearFee {}
impl RPtrRepresentable for PrivateKey {}
impl RPtrRepresentable for StakeCredential {}
impl RPtrRepresentable for TransactionInput {}
impl RPtrRepresentable for TransactionOutput {}
impl RPtrRepresentable for TransactionHash {}
impl RPtrRepresentable for UnitInterval {}
