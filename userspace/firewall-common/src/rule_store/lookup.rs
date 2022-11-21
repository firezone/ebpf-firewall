use super::{end, start, RuleStore, MAX_RANGES};

#[cfg(not(feature = "user"))]
const MAX_ITER: u32 = MAX_RANGES.ilog2() + 1;

impl RuleStore {
    // TODO: We need to check if this works in older kernels.
    // If it doesn't we need to use --unroll-loop.
    // We might need to refactor the loop to explicitly use `MAX_ITER`
    // Note: MAX_ITER is at most 17 if MAX_RULES is 65535 which is the maximum value
    // that'd ever make sense.
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
        if size >= MAX_RANGES {
            return false;
        }
        let mut left = 0;
        let mut right = size;
        #[cfg(not(feature = "user"))]
        let mut i = 0;
        while left < right {
            let mid = left + size / 2;

            // This can never happen but we need the verifier to believe us
            let r = if mid < MAX_RANGES {
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
            let indx = left - 1;
            if indx >= MAX_RANGES {
                return false;
            }
            // SAFETY: Again, we are already bound checking
            end(*unsafe { self.rules.get_unchecked(indx) }) >= val
        }
    }
}
