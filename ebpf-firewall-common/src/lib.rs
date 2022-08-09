#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub source: [u8; 4],
    pub dest: [u8; 4],
    pub action: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
