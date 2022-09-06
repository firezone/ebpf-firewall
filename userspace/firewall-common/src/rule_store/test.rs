#![cfg(test)]

use crate::{
    rule_store::{end, new_rule, proto, start},
    RuleStore, RuleStoreError, GENERIC_PROTO,
};
use test_case::test_case;

use super::MAX_RULES;

#[test_case(10, 20, 6)]
#[test_case(100, 240, 80)]
#[test_case(0, 65535, 255)]
#[test_case(1111, 11111, 4)]
#[test_case(90, 445, 0)]
fn test_well_formed_rules(port_start: u16, port_end: u16, port_proto: u8) {
    let rule = new_rule(port_start, port_end, port_proto);
    assert_eq!(start(rule), port_start);
    assert_eq!(end(rule), port_end);
    assert_eq!(proto(rule), port_proto);
}

#[test_case(4, 0x06, true)]
#[test_case(4, 0x11, true)]
#[test_case(5, 0x22, true)]
#[test_case(3, 0x11, true)]
#[test_case(6, 0x06, true)]
#[test_case(21, 0x11, false)]
#[test_case(21, 0x06, true)]
#[test_case(28, 0x06, true)]
#[test_case(50, 0x06, true)]
#[test_case(10, 0x06, true)]
#[test_case(6000, 0x11, true)]
#[test_case(6000, 0x06, false)]
#[test_case(8000, 0x06, false)]
#[test_case(8000, 0x11, false)]
#[test_case(8000, 0x33, false)]
fn add_rule(port: u16, port_proto: u8, is_contained: bool) {
    let mut rule_store = RuleStore::default();
    rule_store.add(10, 50, 0x06).unwrap();
    rule_store.add(3, 6, GENERIC_PROTO).unwrap();
    rule_store.add(6000, 6000, 0x11).unwrap();
    assert_eq!(rule_store.lookup(port, port_proto), is_contained);
}

#[test]
fn test_exhausted_error() {
    let mut rule_store = RuleStore::default();
    for i in 0..MAX_RULES {
        rule_store.add(i as u16, i as u16, GENERIC_PROTO).unwrap();
    }
    assert_eq!(
        rule_store.add(
            (MAX_RULES + 1) as u16,
            (MAX_RULES + 1) as u16,
            GENERIC_PROTO
        ),
        Err(RuleStoreError::Exhausted)
    );
}
