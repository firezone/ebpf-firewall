#![cfg(feature = "user")]

use crate::action_store::{new_rule, MAX_RULES};
use crate::{Action, ActionStore};
use thiserror::Error;

impl ActionStore {
    pub fn add(
        &mut self,
        start: u16,
        end: u16,
        action: Action,
        proto: u8,
    ) -> Result<(), ActionStoreError> {
        if (self.rules_len as usize) < MAX_RULES {
            self.rules[self.rules_len as usize] = new_rule(start, end, action, proto);
            self.rules_len += 1;
            Ok(())
        } else {
            Err(ActionStoreError::Exhausted)
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ActionStoreError {
    #[error("maximum number of rules for entry reached")]
    Exhausted,
}
