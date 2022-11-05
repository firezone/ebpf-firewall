#![cfg(test)]

use crate::{
    rule_store::{end, new_rule, start},
    RuleStore, RuleStoreError,
};
use test_case::test_case;

use super::MAX_RANGES;

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

#[test_case(4, true)]
#[test_case(5, true)]
#[test_case(3, true)]
#[test_case(6, true)]
#[test_case(7, true)]
#[test_case(21, true)]
#[test_case(28, true)]
#[test_case(87, true)]
#[test_case(50, true)]
#[test_case(10, true)]
#[test_case(6000, true)]
#[test_case(8000, true)]
fn port_0_matches_all(port: u16, is_contained: bool) {
    let rule_store = RuleStore::new(&[(0, 0)]).unwrap();
    assert_eq!(rule_store.lookup(port), is_contained);
}

#[test]
fn test_exhausted_error() {
    let ports: Vec<_> = (0..(MAX_RANGES + 1) as u16).map(|i| (i, i)).collect();
    let rule_store = RuleStore::new(&ports[..]);
    assert!(rule_store.is_err());
    assert_eq!(rule_store.unwrap_err(), RuleStoreError::Exhausted);
}

#[test]
fn test_struct_alignment() {
    assert_eq!(core::mem::size_of::<RuleStore>(), (MAX_RANGES * 4) + 4);
}

#[test_case(10, 20)]
#[test_case(100, 240)]
#[test_case(0, 65535)]
#[test_case(1111, 11111)]
#[test_case(90, 445)]
fn test_well_formed_rules(port_start: u16, port_end: u16) {
    let rule = new_rule(port_start, port_end);
    assert_eq!(start(rule), port_start);
    assert_eq!(end(rule), port_end);
}
