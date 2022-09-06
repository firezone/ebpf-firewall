#![cfg(feature = "user")]

use crate::rule_store::{new_rule, RuleStore, MAX_RULES};
use thiserror::Error;

impl RuleStore {
    pub fn add(&mut self, start: u16, end: u16, proto: u8) -> Result<(), RuleStoreError> {
        if (self.rules_len as usize) < MAX_RULES {
            self.rules[self.rules_len as usize] = new_rule(start, end, proto);
            self.rules_len += 1;
            Ok(())
        } else {
            Err(RuleStoreError::Exhausted)
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Error, PartialEq)]
pub enum RuleStoreError {
    #[error("maximum number of rules for entry reached")]
    Exhausted,
}
