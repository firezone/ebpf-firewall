#![cfg_attr(not(feature = "user"), no_std)]

mod action_store;

pub use action_store::ActionStore;

#[cfg(feature = "user")]
pub use action_store::ActionStoreError;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct PacketLog {
    pub source: [u8; 4],
    pub dest: [u8; 4],
    pub action: i32,
    // 32 instead of 16 for padding
    pub port: u32,
}

#[cfg(feature = "user")]
impl std::fmt::Display for PacketLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use std::net::Ipv4Addr;

        write!(
            f,
            "ipv4: source {} destination {} action {} port {}",
            Ipv4Addr::from(self.source),
            Ipv4Addr::from(self.dest),
            self.action,
            self.port
        )
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
