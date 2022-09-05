#![cfg(test)]

use crate::rule_store::{end, new_rule, proto, start};
use test_case::test_case;

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
