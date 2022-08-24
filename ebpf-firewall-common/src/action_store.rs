mod test;
mod user;

#[cfg(feature = "user")]
pub use user::ActionStoreError;

// 2048 causes a stack overflow, be very careful about this value!
pub const MAX_RULES: usize = 1024;
const START_MASK: u64 = 0x00000000_0000_FFFF;
const END_MASK: u64 = 0x00000000_FFFF_0000;
const END_FIRST_BIT: u64 = 16;
const ACTION_BIT: u64 = 32;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct ActionStore {
    /// bit 0-15 port range start
    /// bit 16-31 port range end
    /// bit 32 action
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

// We don't need action mask if actions are well-formed
// (it's a single bit and after action it's all padding)
// Normally I'd not do this optimization but we do want to get as much performance as possible here
#[inline]
fn action(rule: u64) -> bool {
    (rule >> ACTION_BIT) != 0
}

impl ActionStore {
    // TODO: Use an enum for Action
    pub fn lookup(&self, val: u16) -> Option<bool> {
        // TODO: We can optimize by sorting
        for rule in self.rules.iter().take(self.rules_len as usize) {
            if contains(*rule, val) {
                return Some(action(*rule));
            }
        }

        None
    }
}

#[cfg(any(test, feature = "user"))]
#[inline]
fn new_rule(start: u16, end: u16, action: bool) -> u64 {
    ((action as u64) << ACTION_BIT) | ((end as u64) << END_FIRST_BIT) | (start as u64)
}

impl Default for ActionStore {
    fn default() -> Self {
        Self {
            rules: [0; MAX_RULES],
            rules_len: 0,
        }
    }
}

fn contains(rule: u64, val: u16) -> bool {
    start(rule) <= val && val <= end(rule)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ActionStore {}
