#![cfg_attr(not(feature = "user"), no_std)]
#![cfg_attr(not(feature = "user"), feature(int_log))]
mod rule_store;

pub use rule_store::{Action, RuleStore, GENERIC_PROTO};

#[cfg(feature = "user")]
pub use rule_store::RuleStoreError;
use strum_macros::EnumCount;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct PacketLog {
    pub source: [u8; 16],
    pub dest: [u8; 16],
    pub action: i32,
    pub dest_port: u16,
    pub src_port: u16,
    pub proto: u8,
    pub version: u8,
    pub class: Option<[u8; 16]>,
}

#[repr(u8)]
#[derive(Clone, Copy, EnumCount)]
pub enum ConfigOpt {
    DefaultAction = 0,
}

// Safety ConfigOpt is repr(u8)
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConfigOpt {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
