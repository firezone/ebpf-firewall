#![cfg_attr(not(feature = "user"), no_std)]

mod action_store;

pub use action_store::ActionStore;
pub use action_store::GENERIC_PROTO;

#[cfg(feature = "user")]
pub use action_store::ActionStoreError;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct PacketLog {
    pub source: [u8; 4],
    pub dest: [u8; 4],
    pub action: i32,
    pub port: u16,
    // 8 bits proto,
    // 8 bits padding,
    pub proto: u16,
}

#[cfg(feature = "user")]
impl std::fmt::Display for PacketLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use std::net::Ipv4Addr;

        write!(
            f,
            "ipv4: source {} destination {} action {} port {} proto {}",
            Ipv4Addr::from(self.source),
            Ipv4Addr::from(self.dest),
            self.action,
            self.port,
            self.proto
        )
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
