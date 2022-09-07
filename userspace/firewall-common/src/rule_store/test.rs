#![cfg(test)]

use crate::{RuleStore, RuleStoreError};
use test_case::test_case;

use super::MAX_RULES;

#[test_case(4, true)]
#[test_case(5, true)]
#[test_case(3, true)]
#[test_case(6, true)]
#[test_case(7, false)]
#[test_case(21, true)]
#[test_case(28, true)]
#[test_case(87, false)]
#[test_case(50, true)]
#[test_case(10, true)]
#[test_case(6000, true)]
#[test_case(8000, false)]
#[test_case(0, false)]
fn add_rule(port: u16, is_contained: bool) {
    let rule_store = RuleStore::new(&[(3, 6), (10, 50), (6000, 6000)]).unwrap();
    assert_eq!(rule_store.lookup(port), is_contained);
}

#[test]
fn test_exhausted_error() {
    let ports: Vec<_> = (0..(MAX_RULES + 1) as u16).map(|i| (i, i)).collect();
    let rule_store = RuleStore::new(&ports[..]);
    assert!(rule_store.is_err());
    assert_eq!(rule_store.unwrap_err(), RuleStoreError::Exhausted);
}
