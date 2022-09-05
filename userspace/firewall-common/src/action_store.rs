mod test;
mod user;

#[cfg(feature = "user")]
pub use user::ActionStoreError;

// 2048 causes a stack overflow, be very careful about this value!
pub const MAX_RULES: usize = 500;
// 0xFF should be reserved so this should work forever....
// We have some free bytes in ActionStore we could as well use a u16 and 0x0100
pub const GENERIC_PROTO: u8 = 0xFF;
const START_MASK: u64 = 0x00000000_0000_FFFF;
const END_MASK: u64 = 0x00000000_FFFF_0000;
const END_FIRST_BIT: u64 = 16;
const PROTO_MASK: u64 = 0x0000_FF00_0000_0000;
const PROTO_FIRST_BIT: u64 = 40;

// This are also defined in aya-bpf::bindings
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

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ActionStore {
    /// bit 0-15 port range start
    /// bit 16-31 port range end
    /// bit 40-47 port proto
    /// rest padding
    rules: [u64; MAX_RULES],
    /// Keep this to < usize::MAX pretty please
    /// But we do need the padding
    rules_len: u64,
}

#[inline]
fn start(rule: u64) -> u16 {
    (rule & START_MASK) as u16
}

#[inline]
fn end(rule: u64) -> u16 {
    ((rule & END_MASK) >> END_FIRST_BIT) as u16
}

#[inline]
fn proto(rule: u64) -> u8 {
    ((rule & PROTO_MASK) >> PROTO_FIRST_BIT) as u8
}

impl ActionStore {
    // TODO: Use an enum for Action
    // Here we have 2 problems:
    // Firstly, this is a loop, and bounded loops are supported by kernel 5.3 and onwards
    // This can be helped, sometimes, by using the aya-linker flag --unroll-loops
    // Furthemore, this can limit the number of rules due to too many jumps or insts for the verifier
    // we need to revisit the loop, maybe do some unrolling ourselves or look for another way
    pub fn lookup(&self, val: u16, proto: u8) -> bool {
        // TODO: We can optimize by sorting
        for rule in self.rules.iter().take(self.rules_len as usize) {
            if contains(*rule, val, proto) {
                return true;
            }
        }

        false
    }
}

#[cfg(any(test, feature = "user"))]
#[inline]
fn new_rule(start: u16, end: u16, proto: u8) -> u64 {
    ((proto as u64) << PROTO_FIRST_BIT) | ((end as u64) << END_FIRST_BIT) | (start as u64)
}

impl Default for ActionStore {
    fn default() -> Self {
        Self {
            rules: [0; MAX_RULES],
            rules_len: 0,
        }
    }
}

fn contains(rule: u64, val: u16, prot: u8) -> bool {
    // TODO: This allocates and then just compares (call + mov + 2 x cmp)
    // Would just be calling proto twice be faster? (2 x (call + cmp))
    let proto = proto(rule);
    (proto == GENERIC_PROTO || proto == prot) && start(rule) <= val && val <= end(rule)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ActionStore {}
