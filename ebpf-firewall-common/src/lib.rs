#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub source: [u8; 4],
    pub dest: [u8; 4],
    pub action: i32,
    // 32 instead of 16 for padding
    pub port: u32,
}

pub const MAX_RULES: usize = 2048;
const START_MASK: u64 = 0x00000000_0000_FFFF;
const END_MASK: u64 = 0x00000000_FFFF_0000;
const END_FIRST_BIT: u64 = 16;
const ACTION_BIT: u64 = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActionStore {
    /// bit 0-15 port range start
    /// bit 16-31 port range end
    /// bit 32 action
    /// rest padding
    rules: [u64; MAX_RULES],
    /// Keep this to < usize pretty please
    /// But we do need the padding
    rules_len: u64,
}

fn new_rule(start: u16, end: u16, action: bool) -> u64 {
    ((action as u64) << ACTION_BIT) | ((end as u64) << END_FIRST_BIT) | (start as u64)
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
                // Here we implicitly prioritize the earliest rule
                // We could have much better prioritization
                return Some(action(*rule));
            }
        }

        None
    }

    // TODO: use u64 to prevent cast or templatize this
    // Also todo, errors!
    pub fn add(&mut self, start: u16, end: u16, action: bool) -> Result<(), ()> {
        if (self.rules_len as usize) < MAX_RULES {
            self.rules[self.rules_len as usize] = new_rule(start, end, action);
            self.rules_len += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn new() -> Self {
        Self {
            rules: [0; MAX_RULES],
            rules_len: 0,
        }
    }

    // I wanted to use aya::Pod to say that this struct is basically an array, however
    // That lead to some weird! behavior, need more investigation as to if and how to make
    // this more ergonomic
    pub fn as_array(self) -> [u64; MAX_RULES + 1] {
        let mut res = [0; MAX_RULES + 1];
        let (rules, rules_len) = res.split_at_mut(MAX_RULES);
        rules.copy_from_slice(&self.rules[..]);
        rules_len.copy_from_slice(&[self.rules_len]);
        res
    }
}

fn contains(rule: u64, val: u16) -> bool {
    start(rule) <= val && val <= end(rule)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(test)]
mod test {
    use crate::{action, end, new_rule, start};

    #[test]
    fn valid_rule() {
        let rule = new_rule(10, 20, true);
        assert_eq!(start(rule), 10);
        assert_eq!(end(rule), 20);
        assert_eq!(action(rule), true);
    }
}
