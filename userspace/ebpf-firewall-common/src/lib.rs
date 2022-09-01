#![cfg_attr(not(feature = "user"), no_std)]

mod action_store;

pub use action_store::GENERIC_PROTO;
pub use action_store::{Action, ActionStore};

#[cfg(feature = "user")]
pub use action_store::ActionStoreError;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct PacketLog {
    pub source: [u8; 16],
    pub dest: [u8; 16],
    pub action: i32,
    pub port: u16,
    pub proto: u8,
    pub version: u8,
}

#[cfg(feature = "user")]
impl std::fmt::Display for PacketLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use std::net::Ipv4Addr;
        use std::net::Ipv6Addr;

        match self.version {
            4 => {
                let source = self.source;
                let dest = self.dest;
                write!(
                    f,
                    "ipv4: source {} destination {} action {} port {} proto {}",
                    Ipv4Addr::from([source[0], source[1], source[2], source[3]]),
                    Ipv4Addr::from([dest[0], dest[1], dest[2], dest[3]]),
                    self.action,
                    self.port,
                    self.proto
                )
            }
            6 => write!(
                f,
                "ipv6: source {} destination {} action {} port {} proto {}",
                Ipv6Addr::from(self.source),
                Ipv6Addr::from(self.dest),
                self.action,
                self.port,
                self.proto
            ),
            _ => write!(f, "Network Protocol Unkown: {}", self.version),
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
