mod test;
mod user;

#[cfg(feature = "user")]
pub use user::RuleStoreError;

pub const MAX_RULES: usize = 1024;
#[cfg(not(feature = "user"))]
const MAX_ITER: u32 = MAX_RULES.ilog2() + 1;
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

impl RuleStore {
    // TODO: We need to check if this works in older kernels.
    // If it doesn't we need to use --unroll-loop.
    // We might need to refactor the loop to explicitly use `MAX_ITER`
    // Note: MAX_ITER is a most 16
    pub fn lookup(&self, val: u16) -> bool {
        // 0 means all ports
        if self.rules_len > 0 {
            // SAFETY: We know that rules_len < MAX_RULES
            if start(*unsafe { self.rules.get_unchecked(0) }) == 0 {
                return true;
            }
        }

        // We test for 0 in all non tcp/udp packets
        // it's worth returning early for those cases.
        if val == 0 {
            return false;
        }

        // Reimplementation of partition_point to satisfy verifier
        let mut size = self.rules_len as usize;
        // appeasing the verifier
        if size >= MAX_RULES {
            return false;
        }
        let mut left = 0;
        let mut right = size;
        #[cfg(not(feature = "user"))]
        let mut i = 0;
        while left < right {
            let mid = left + size / 2;

            // This can never happen but we need the verifier to believe us
            let r = if mid < MAX_RULES {
                // SAFETY: We are already bound checking
                *unsafe { self.rules.get_unchecked(mid) }
            } else {
                return false;
            };
            let cmp = start(r) <= val;
            if cmp {
                left = mid + 1;
            } else {
                right = mid;
            }
            size = right - left;
            #[cfg(not(feature = "user"))]
            {
                i += 1;
                // This should never happen, here just to satisfy verifier
                if i >= MAX_ITER {
                    return false;
                }
            }
        }

        if left == 0 {
            false
        } else {
            if left >= MAX_RULES {
                return false;
            }
            // SAFETY: Again, we are already bound checking
            end(*unsafe { self.rules.get_unchecked(left - 1) }) >= val
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleStore {}
