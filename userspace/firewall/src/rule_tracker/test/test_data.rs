/*
*/

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Cidr},
    rule_tracker::to_rule_store,
    Protocol,
    Protocol::Generic,
    Protocol::TCP,
    Protocol::UDP,
    Rule, RuleTracker,
};

pub(crate) fn prepare_ipv4() -> RuleTracker<Ipv4Addr, ()> {
    let mut rule_tracker = RuleTracker::<Ipv4Addr, _>::new_test().unwrap();

    let cidr = "10.1.1.3/32".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(10..=20, Generic))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(15..=20, Generic))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(15..=25, Generic))
        .unwrap();
    let cidr = "10.1.0.0/16".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(200..=500, UDP))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(12..=16, TCP))
        .unwrap();
    let cidr = "10.1.1.3/32".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(18..=40, Generic))
        .unwrap();
    let cidr = "10.1.1.0/24".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(200..=800, UDP))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(999..=999, TCP))
        .unwrap();
    let cidr = "10.1.0.0/16".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(6000..=8000, TCP))
        .unwrap();
    rule_tracker
}

pub(crate) fn prepare_ipv6() -> RuleTracker<Ipv6Addr, ()> {
    let mut rule_tracker = RuleTracker::<Ipv6Addr, _>::new_test().unwrap();

    let cidr = "fafa::1:0:0:3/128".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(10..=20, Generic))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(15..=20, Generic))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(15..=25, Generic))
        .unwrap();
    let cidr = "fafa::/64".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(200..=500, UDP))
        .unwrap();
    rule_tracker
        .add_rule(&rule.with_range(12..=16, TCP))
        .unwrap();
    let cidr = "fafa::1:0:0:3/128".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(18..=40, Generic))
        .unwrap();
    let cidr = "fafa::1:0:0:0/96".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(200..=800, UDP))
        .unwrap();
    rule_tracker
        .add_rule(&rule.clone().with_range(999..=999, TCP))
        .unwrap();
    let cidr = "fafa::/64".parse().unwrap();
    let rule = Rule::new(cidr);
    rule_tracker
        .add_rule(&rule.clone().with_range(6000..=8000, TCP))
        .unwrap();
    rule_tracker
}

pub(crate) fn prepared_expect_v6(test_run: TestRun<Ipv6Addr>) -> TestRun<Ipv6Addr> {
    test_run
        .expect_true(
            "fafa::1:0:0:3/128",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (UDP, 200),
                (UDP, 800),
                (TCP, 999),
                (TCP, 7000),
            ],
        )
        .expect_false("fafa::0:0:3/128", &[(TCP, 200), (TCP, 800), (UDP, 999)])
        .expect_true(
            "fafa::1:0:0:0/96",
            &[(UDP, 200), (UDP, 800), (TCP, 999), (TCP, 7000)],
        )
        .expect_false(
            "fafa::1:0:0:0/96",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (TCP, 200),
                (TCP, 800),
                (UDP, 999),
                (UDP, 7000),
            ],
        )
        .expect_true("fafa::/64", &[(UDP, 200), (TCP, 7000)])
        .expect_false(
            "fafa::/64",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (TCP, 200),
                (Generic, 800),
                (UDP, 7000),
            ],
        )
}

pub(crate) fn prepared_expect_v4(test_run: TestRun<Ipv4Addr>) -> TestRun<Ipv4Addr> {
    test_run
        .expect_true(
            "10.1.1.3/32",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (UDP, 200),
                (UDP, 800),
                (TCP, 999),
                (TCP, 7000),
            ],
        )
        .expect_false("10.1.1.3/32", &[(TCP, 200), (TCP, 800), (UDP, 999)])
        .expect_true(
            "10.1.1.0/24",
            &[(UDP, 200), (UDP, 800), (TCP, 999), (TCP, 7000)],
        )
        .expect_false(
            "10.1.1.0/24",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (TCP, 200),
                (TCP, 800),
                (UDP, 999),
                (UDP, 7000),
            ],
        )
        .expect_true("10.1.0.0/16", &[(UDP, 200), (TCP, 7000)])
        .expect_false(
            "10.1.0.0/16",
            &[
                (Generic, 10),
                (Generic, 20),
                (Generic, 25),
                (TCP, 200),
                (Generic, 800),
                (UDP, 7000),
            ],
        )
}

type Port = (Protocol, u16);
#[derive(Debug)]
pub(crate) struct TestRun<T>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone + AsOctets,
    Cidr<T>: AsKey,
    T::Octets: AsRef<[u8]>,
{
    rule_tracker: RuleTracker<T, ()>,
    expect_true: HashMap<(u32, Cidr<T>), HashSet<Port>>,
    expect_false: HashMap<(u32, Cidr<T>), HashSet<Port>>,
}

impl<T> TestRun<T>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone + AsOctets + FromStr<Err = AddrParseError>,
    Cidr<T>: AsKey,
    T::Octets: AsRef<[u8]>,
    T: Debug,
{
    pub(crate) fn run(&self) {
        println!("{self:#?}");
        for ((id, cidr), ports) in self.expect_true.clone() {
            for (proto, port) in ports {
                let rule_map = self.rule_tracker.rule_map.get(&(id, proto, cidr.clone()));
                assert!(
                    rule_map.is_some(),
                    "rule_map for id {id} cidr {cidr:?} protocol {proto:?} port {port:?} is none"
                );
                let rule_store = to_rule_store(rule_map.unwrap().clone());
                assert!(
                    rule_store.lookup(port),
                    "port {port} not contained in {cidr:?} with proto {proto:?} for id {id:?}"
                );
            }
        }

        for ((id, cidr), ports) in self.expect_false.clone() {
            for (proto, port) in ports {
                let rule_map = self.rule_tracker.rule_map.get(&(id, proto, cidr.clone()));
                if !rule_map.is_none() {
                    let rule_store = to_rule_store(rule_map.unwrap().clone());
                    assert!(
                        !rule_store.lookup(port),
                        "port {port} is contained in {cidr:#?} with proto {proto:?} for id {id:?}"
                    );
                }
            }
        }
    }

    pub(crate) fn with(rule_tracker: RuleTracker<T, ()>) -> Self {
        Self {
            rule_tracker,
            expect_true: Default::default(),
            expect_false: Default::default(),
        }
    }

    pub(crate) fn expect_true(mut self, cidr: impl AsRef<str>, ports: &[Port]) -> Self {
        let cidr: Cidr<T> = cidr.as_ref().parse().unwrap();

        let ports: HashSet<_> = ports
            .iter()
            .flat_map(|p| {
                if p.0 == Generic {
                    let mut vec = Vec::new();
                    vec.push((UDP, p.1));
                    vec.push((TCP, p.1));
                    vec.into_iter()
                } else {
                    let mut vec = Vec::new();
                    vec.push(*p);
                    vec.into_iter()
                }
            })
            .collect();
        self.expect_true
            .entry((0, cidr.clone()))
            .and_modify(|e| e.extend(ports.iter()))
            .or_insert(ports.clone());

        if let Some(res) = self.expect_false.get_mut(&(0, cidr)) {
            res.retain(|p| !ports.contains(p))
        }

        self
    }

    pub(crate) fn expect_false(mut self, cidr: impl AsRef<str>, ports: &[Port]) -> Self {
        let cidr: Cidr<T> = cidr.as_ref().parse().unwrap();

        let ports: HashSet<_> = ports
            .iter()
            .flat_map(|p| {
                if p.0 == Generic {
                    let mut vec = Vec::new();
                    vec.push((UDP, p.1));
                    vec.push((TCP, p.1));
                    vec.into_iter()
                } else {
                    let mut vec = Vec::new();
                    vec.push(*p);
                    vec.into_iter()
                }
            })
            .collect();
        self.expect_false
            .entry((0, cidr.clone()))
            .and_modify(|e| e.extend(ports.iter()))
            .or_insert(ports.clone());

        if let Some(res) = self.expect_true.get_mut(&(0, cidr)) {
            res.retain(|p| !ports.contains(p))
        }

        self
    }
}
