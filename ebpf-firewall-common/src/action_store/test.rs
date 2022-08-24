#![cfg(test)]

use crate::action_store::{action, end, new_rule, start};

#[test]
fn valid_rule() {
    let rule = new_rule(10, 20, true);
    assert_eq!(start(rule), 10);
    assert_eq!(end(rule), 20);
    assert_eq!(action(rule), true);
}
