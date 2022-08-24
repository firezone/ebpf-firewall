#![cfg(test)]

use crate::action_store::{action, end, new_rule, proto, start};
use test_case::test_case;

#[test_case(10, 20, true, 6)]
#[test_case(100, 240, false, 80)]
#[test_case(0, 65535, false, 255)]
#[test_case(1111, 11111, true, 4)]
#[test_case(90, 445, false, 0)]
fn test_well_formed_rules(port_start: u16, port_end: u16, port_action: bool, port_proto: u8) {
    let rule = new_rule(port_start, port_end, port_action, port_proto);
    assert_eq!(start(rule), port_start);
    assert_eq!(end(rule), port_end);
    assert_eq!(action(rule), port_action);
    assert_eq!(proto(rule), port_proto);
}
