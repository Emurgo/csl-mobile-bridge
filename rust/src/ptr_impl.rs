use crate::ptr::RPtrRepresentable;
use cddl_lib::address::*;
use cddl_lib::crypto::*;
use cddl_lib::{UnitInterval};

impl RPtrRepresentable for Address {}
impl RPtrRepresentable for AddrKeyHash {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for StakeCredential {}
impl RPtrRepresentable for UnitInterval {}
