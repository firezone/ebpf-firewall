#![cfg(test)]

use aya::Pod;
use test_case::test_case;

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Cidr},
    rule_tracker::to_rule_store,
    Ipv4CIDR, Ipv6CIDR,
    Protocol::{self, Generic, TCP, UDP},
    Result, RuleTracker,
};

use core::fmt::Debug;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

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

impl<T> RuleTracker<T, ()>
where
    T: AsNum + From<T::Num> + Debug,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    pub fn new_test() -> Result<Self> {
        Ok(Self {
            rule_map: HashMap::new(),
            ebpf_store: (),
        })
    }
}

fn prepare_ipv4() -> RuleTracker<Ipv4Addr, ()> {
    let id = 0;
    let mut rule_tracker = RuleTracker::<Ipv4Addr, _>::new_test().unwrap();

    let cidr = Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32);
    rule_tracker.add_rule(id, cidr, 10..=20, Generic).unwrap();
    rule_tracker.add_rule(id, cidr, 15..=20, Generic).unwrap();
    rule_tracker.add_rule(id, cidr, 15..=25, Generic).unwrap();
    let cidr = Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16);
    rule_tracker.add_rule(id, cidr, 200..=500, TCP).unwrap();
    rule_tracker.add_rule(id, cidr, 12..=16, TCP).unwrap();
    let cidr = Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32);
    rule_tracker.add_rule(id, cidr, 18..=40, Generic).unwrap();
    let cidr = Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24);
    rule_tracker.add_rule(id, cidr, 200..=800, UDP).unwrap();
    rule_tracker.add_rule(id, cidr, 999..=999, TCP).unwrap();
    let cidr = Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16);
    rule_tracker.add_rule(id, cidr, 6000..=8000, TCP).unwrap();
    rule_tracker
}

fn prepare_ipv6() -> RuleTracker<Ipv6Addr, ()> {
    let id = 0;
    let mut rule_tracker = RuleTracker::<Ipv6Addr, _>::new_test().unwrap();

    let cidr = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128);
    rule_tracker.add_rule(id, cidr, 10..=20, Generic).unwrap();
    rule_tracker.add_rule(id, cidr, 15..=20, Generic).unwrap();
    rule_tracker.add_rule(id, cidr, 15..=25, Generic).unwrap();
    let cidr = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64);
    rule_tracker.add_rule(id, cidr, 200..=500, TCP).unwrap();
    rule_tracker.add_rule(id, cidr, 12..=16, TCP).unwrap();
    let cidr = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128);
    rule_tracker.add_rule(id, cidr, 18..=40, Generic).unwrap();
    let cidr = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96);
    rule_tracker.add_rule(id, cidr, 200..=800, UDP).unwrap();
    rule_tracker.add_rule(id, cidr, 999..=999, TCP).unwrap();
    let cidr = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64);
    rule_tracker.add_rule(id, cidr, 6000..=8000, TCP).unwrap();
    rule_tracker
}

#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 10, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 10, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 20, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 20, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 25, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 25, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 200, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 200, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 800, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 800, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 999, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 999, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 7000, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 3), 32), 7000, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 10, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 10, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 20, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 20, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 25, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 25, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 200, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 200, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 800, UDP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 800, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 999, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 999, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 7000, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 1, 0), 24), 7000, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 10, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 10, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 20, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 20, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 25, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 25, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 200, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 200, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 800, UDP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 800, TCP, false)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 7000, TCP, true)]
#[test_case(0, Ipv4CIDR::new(Ipv4Addr::new(10, 1, 0, 0), 16), 7000, UDP, false)]
fn add_ipv4_rule_works(id: u32, cidr: Ipv4CIDR, port: u16, proto: Protocol, assert: bool) {
    let rule_tracker = prepare_ipv4();

    if let Some(rule_set) = rule_tracker.rule_map.get(&(id, proto, cidr)) {
        let rule_store = to_rule_store(rule_set.clone());
        println!("{rule_store:?}");
        assert_eq!(rule_store.lookup(port), assert);
    } else {
        assert!(!assert);
    }
}

#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 10, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 10, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 20, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 20, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 25, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 25, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 200, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 200, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 800, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 800, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 999, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 999, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 7000, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128), 7000, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 10, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 10, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 20, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 20, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 25, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 25, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 200, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 200, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 800, UDP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 800, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 999, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 999, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 7000, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96), 7000, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 10, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 10, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 20, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 20, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 25, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 25, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 200, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 200, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 800, UDP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 800, TCP, false)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 7000, TCP, true)]
#[test_case(0, Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64), 7000, UDP, false)]
fn add_ipv6_rule_works(id: u32, cidr: Ipv6CIDR, port: u16, proto: Protocol, assert: bool) {
    let rule_tracker = prepare_ipv6();
    if let Some(rule_set) = rule_tracker.rule_map.get(&(id, proto, cidr)) {
        let rule_store = to_rule_store(rule_set.clone());
        assert_eq!(rule_store.lookup(port), assert);
    } else {
        assert!(!assert)
    }
}
