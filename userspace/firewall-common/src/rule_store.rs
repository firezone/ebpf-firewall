mod lookup;
mod test;
mod user;

#[cfg(feature = "user")]
pub use user::RuleStoreError;

pub const MAX_RULES: usize = 1024;
// 0xFF should be reserved so this should work forever....
// We have some free bytes in RuleStore we could as well use a u16 and 0x0100
pub const GENERIC_PROTO: u8 = 0xFF;

// These are also defined in aya-bpf::bindings
// Based on these tc-bpf man https://man7.org/linux/man-pages/man8/tc-bpf.8.html
// We redefine them here as not to depend on aya-bpf in this crate
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Debug, Hash))]
pub enum Action {
    Accept = TC_ACT_OK,
    Reject = TC_ACT_SHOT,
}

impl Default for Action {
    fn default() -> Self {
        Self::Reject
    }
}

const START_MASK: u32 = 0x0000_FFFF;
const END_MASK: u32 = 0xFFFF_0000;
const END_FIRST_BIT: u32 = 16;

#[inline]
fn start(rule: u32) -> u16 {
    (rule & START_MASK) as u16
}

#[inline]
fn end(rule: u32) -> u16 {
    ((rule & END_MASK) >> END_FIRST_BIT) as u16
}

#[cfg(any(test, feature = "user"))]
#[inline]
fn new_rule(start: u16, end: u16) -> u32 {
    ((end as u32) << END_FIRST_BIT) | (start as u32)
}

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct RuleStore {
    // Sorted non-overlapping ranges
    // bit 0-15: port-start
    // bit 16-31: port-end
    rules: [u32; MAX_RULES],
    /// Keep this to < usize::MAX pretty please
    /// But we do need the padding
    rules_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleStore {}
