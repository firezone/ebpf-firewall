#![cfg(feature = "user")]

use crate::rule_store::{RuleStore, MAX_RANGES};
use thiserror::Error;

use super::new_rule;

impl RuleStore {
    pub fn new(ports: &[(u16, u16)]) -> Result<RuleStore, RuleStoreError> {
        if ports.len() <= MAX_RANGES {
            if Self::wellformed(ports) {
                let mut rules = [0u32; MAX_RANGES];
                let rule_len = ports.len();
                rules[..rule_len]
                    .copy_from_slice(&ports.iter().map(|p| new_rule(p.0, p.1)).collect::<Vec<_>>());
                Ok(RuleStore {
                    rules,
                    rules_len: (rule_len as u32),
                })
            } else {
                Err(RuleStoreError::MalFormed)
            }
        } else {
            Err(RuleStoreError::Exhausted)
        }
    }

    fn wellformed(ports: &[(u16, u16)]) -> bool {
        // is_sorted is not stable yet
        let mut last_start = None;
        let mut last_end = None;
        let mut sorted = true;
        let mut interval = true;
        let mut non_overlaping = true;
        for (a, b) in ports {
            if last_start.is_none() {
                last_start = Some(a);
            }
            sorted = sorted && a >= last_start.unwrap();
            interval = interval && b >= a;
            non_overlaping = non_overlaping && (last_end.is_none() || last_end.unwrap() < a);
            last_start = Some(a);
            last_end = Some(b);
        }
        sorted && interval && non_overlaping
    }
}

#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleStoreError {
    #[error("maximum number of rules for entry reached")]
    Exhausted,
    #[error("overlapping rules or not sorted")]
    MalFormed,
}
