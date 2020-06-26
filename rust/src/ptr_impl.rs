use crate::ptr::RPtrRepresentable;
use cddl_lib::address::*;
use cddl_lib::crypto::*;

impl RPtrRepresentable for Address {}
impl RPtrRepresentable for AddrKeyHash {}
impl RPtrRepresentable for BaseAddress {}
impl RPtrRepresentable for StakeCredential {}
