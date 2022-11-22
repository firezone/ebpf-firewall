#![cfg(test)]

mod test_data;

use aya::Pod;

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Normalize},
    rule::RuleImpl,
    Protocol::{Generic, UDP},
    Result,
};

use core::fmt::Debug;
use std::collections::HashMap;

use self::test_data::TestRun;

use super::rule_trie::RuleTrie;

impl<K: Pod, V: Pod> RuleTrie<K, V> for () {
    fn insert(
        &mut self,
        _: &aya::maps::lpm_trie::Key<K>,
        _: V,
    ) -> core::result::Result<(), aya::maps::MapError> {
        Ok(())
    }

    fn remove(
        &mut self,
        _: &aya::maps::lpm_trie::Key<K>,
    ) -> core::result::Result<(), aya::maps::MapError> {
        Ok(())
    }
}

impl<T> crate::rule_tracker::RuleTracker<T>
where
    T: AsNum + Debug + AsKey + AsOctets + Normalize,
    T::Octets: AsRef<[u8]>,
{
    pub fn new_test() -> Result<Self> {
        Ok(Self {
            rule_map: HashMap::new(),
        })
    }
}

#[test]
fn add_ipv4_rule_works() {
    let test_run = TestRun::with(test_data::prepare_ipv4());
    test_data::prepared_expect_v4(test_run).run();
}

#[test]
fn port_0_match_all_ip_v4() {
    let mut rule_tracker = test_data::prepare_ipv4();
    rule_tracker
        .add_rule(
            &mut (),
            &RuleImpl::new("10.1.1.0/24".parse().unwrap()).with_range(0..=0, Generic),
        )
        .unwrap();

    let test_run = TestRun::with(rule_tracker);
    test_data::prepared_expect_v4(test_run)
        .expect_true(
            "10.1.1.0/24",
            &(0..65535u16).map(|p| (Generic, p)).collect::<Vec<_>>(),
        )
        .expect_true(
            "10.1.1.3/32",
            &(0..65535u16).map(|p| (Generic, p)).collect::<Vec<_>>(),
        )
        .run();
}

#[test]
fn remove_ipv4_rule_works() {
    let mut rule_tracker = test_data::prepare_ipv4();
    rule_tracker
        .remove_rule(
            &mut (),
            &RuleImpl::new("10.1.1.0/24".parse().unwrap()).with_range(200..=800, UDP),
        )
        .unwrap();

    let test_run = TestRun::with(rule_tracker);
    test_data::prepared_expect_v4(test_run)
        .expect_false("10.1.1.3/32", &[(UDP, 800)])
        .expect_false("10.1.1.0/24", &[(UDP, 800)])
        .run();
}

#[test]
fn add_ipv6_rule_works() {
    let test_run = TestRun::with(test_data::prepare_ipv6());
    test_data::prepared_expect_v6(test_run).run();
}

#[test]
fn port_0_match_all_ip_v6() {
    let mut rule_tracker = test_data::prepare_ipv6();
    rule_tracker
        .add_rule(
            &mut (),
            &RuleImpl::new("fafa::1:0:0:0/96".parse().unwrap()).with_range(0..=0, Generic),
        )
        .unwrap();

    let test_run = TestRun::with(rule_tracker);
    test_data::prepared_expect_v6(test_run)
        .expect_true(
            "fafa::1:0:0:0/96",
            &(0..65535u16).map(|p| (Generic, p)).collect::<Vec<_>>(),
        )
        .expect_true(
            "fafa::1:0:0:3/128",
            &(0..65535u16).map(|p| (Generic, p)).collect::<Vec<_>>(),
        )
        .run();
}

#[test]
fn remove_ipv6_rule_works() {
    let mut rule_tracker = test_data::prepare_ipv6();
    rule_tracker
        .remove_rule(
            &mut (),
            &RuleImpl::new("fafa::1:0:0:0/96".parse().unwrap()).with_range(200..=800, UDP),
        )
        .unwrap();

    let test_run = TestRun::with(rule_tracker);
    test_data::prepared_expect_v6(test_run)
        .expect_false("fafa::1:0:0:3/128", &[(UDP, 800)])
        .expect_false("fafa::1:0:0:0/96", &[(UDP, 800)])
        .run();
}
