use crate::ptr::RPtrRepresentable;
use cardano_serialization_lib::address::*;
use cardano_serialization_lib::crypto::*;
use cardano_serialization_lib::utils::*;
use cardano_serialization_lib::fees::*;
use cardano_serialization_lib::*;

impl RPtrRepresentable for BigNum {}
impl RPtrRepresentable for ByronAddress {}
impl RPtrRepresentable for Address {}
impl RPtrRepresentable for Ed25519KeyHash {}
impl RPtrRepresentable for TransactionHash {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for StakeCredential {}
impl RPtrRepresentable for UnitInterval {}
impl RPtrRepresentable for TransactionInput {}
impl RPtrRepresentable for TransactionOutput {}
impl RPtrRepresentable for LinearFee {}
