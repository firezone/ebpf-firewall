mod test;
mod user;

#[cfg(feature = "user")]
pub use user::RuleStoreError;

pub const MAX_RULES: usize = 512;
// 0xFF should be reserved so this should work forever....
// We have some free bytes in RuleStore we could as well use a u16 and 0x0100
pub const GENERIC_PROTO: u8 = 0xFF;

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
pub struct RuleStore {
    // Sorted non-overlapping ranges
    rules: [(u16, u16); MAX_RULES],
    /// Keep this to < usize::MAX pretty please
    /// But we do need the padding
    rules_len: u32,
}

impl RuleStore {
    // TODO: Use an enum for Action
    // Here we have 2 problems:
    // Firstly, this is a loop, and bounded loops are supported by kernel 5.3 and onwards
    // This can be helped, sometimes, by using the aya-linker flag --unroll-loops
    // Furthemore, this can limit the number of rules due to too many jumps or insts for the verifier
    // we need to revisit the loop, maybe do some unrolling ourselves or look for another way
    pub fn lookup(&self, val: u16) -> bool {
        let rules = &self.rules[..self.rules_len as usize];
        // 0 means all ports
        if let Some(rule) = rules.first() {
            if rule.0 == 0 {
                return true;
            }
        }

        // We test for 0 in all non tcp/udp packets
        // it's worth returning early for those cases.
        if val == 0 {
            return false;
        }

        let point = rules.partition_point(|r| r.0 <= val);
        if point == 0 {
            false
        } else {
            self.rules[point - 1].1 >= val
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleStore {}
