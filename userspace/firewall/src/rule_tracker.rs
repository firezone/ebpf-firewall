mod test;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use aya::maps::lpm_trie::Key;
use firewall_common::{RuleStore, RuleStoreError};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, Contains, Normalize, Normalized},
    rule::{self, Protocol, RuleImpl},
    Error, Result,
};

use crate::bpf_store::BpfStore;

type StoreResult<T = ()> = std::result::Result<T, RuleStoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortRange<T>
where
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    ports: rule::PortRange,
    origin: T,
}

impl<T> PortRange<T>
where
    T: AsOctets + Clone,
    T::Octets: AsRef<[u8]>,
{
    fn unfold(&self) -> Vec<Self> {
        self.ports
            .unfold()
            .iter()
            .map(|ports| PortRange {
                ports: ports.clone(),
                origin: self.origin.clone(),
            })
            .collect()
    }
}

fn to_rule_store<'a, T>(
    port_ranges: impl IntoIterator<Item = &'a PortRange<T>>,
) -> StoreResult<RuleStore>
where
    T: AsOctets + 'a,
    T::Octets: AsRef<[u8]>,
{
    let port_ranges = &mut port_ranges.into_iter().collect::<Vec<_>>()[..];
    RuleStore::new(&resolve_overlap(port_ranges))
}

fn resolve_overlap<T>(port_ranges: &mut [&PortRange<T>]) -> Vec<(u16, u16)>
where
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    let mut res = Vec::new();
    port_ranges.sort_by_key(|p| p.ports.ports.start());
    if let Some(range) = port_ranges.first() {
        res.push((*range.ports.ports.start(), *range.ports.ports.end()));
    } else {
        return res;
    }
    for range in &port_ranges[1..] {
        let last_res = res
            .last_mut()
            .expect("should contain at least the first element of port_ranges");

        if last_res.1 >= *range.ports.ports.start() {
            *last_res = (last_res.0, last_res.1.max(*range.ports.ports.end()));
        } else {
            res.push((*range.ports.ports.start(), *range.ports.ports.end()));
        }
    }
    res
}

pub(crate) type RuleTrackerV4 = RuleTracker<Ipv4Net>;
pub(crate) type RuleTrackerV6 = RuleTracker<Ipv6Net>;

pub(crate) struct RuleTracker<T>
where
    T: AsOctets + AsKey + Normalize,
    T::Octets: AsRef<[u8]>,
{
    rule_map: HashMap<(u128, Protocol, Normalized<T>), HashSet<PortRange<T>>>,
}

impl<T> Debug for RuleTracker<T>
where
    T: AsKey + Normalize + AsOctets + Debug,
    T::Octets: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleTracker")
            .field("rule_map", &self.rule_map)
            .finish()
    }
}

impl RuleTracker<Ipv4Net> {
    pub(crate) fn new() -> Result<Self> {
        Self::new_with_name()
    }
}

impl RuleTracker<Ipv6Net> {
    pub(crate) fn new() -> Result<Self> {
        Self::new_with_name()
    }
}

impl<T> RuleTracker<T>
where
    T: Eq + Hash + Clone + AsKey + Normalize,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn new_with_name() -> Result<Self> {
        Ok(Self {
            rule_map: HashMap::new(),
        })
    }
}

impl<T> RuleTracker<T>
where
    T: AsKey + AsOctets + Eq + Hash + Clone + Normalize + Contains,
    T::Octets: AsRef<[u8]>,
{
    pub(crate) fn add_rule(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        RuleImpl {
            id,
            dest,
            port_range,
        }: &RuleImpl<T>,
    ) -> Result<()> {
        if !port_range_check(port_range) {
            return Err(Error::InvalidPort);
        }

        let port_range = PortRange {
            ports: port_range.clone().unwrap_or_default(),
            origin: dest.clone(),
        };

        // Checks to prevent rollback
        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);

            self.check_range_len(&port_range, id, dest)?;
            self.reverse_propagate_check(store, dest, id, proto)?;
            self.propagate_check(store, port_range, id, proto)?;
        }

        // Apply modifications
        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);

            let port_ranges = self
                .rule_map
                .entry((id, port_range.ports.proto, Normalized::new(dest.clone())))
                .and_modify(|e| {
                    e.insert(port_range.clone());
                })
                .or_insert_with(|| HashSet::from([port_range.clone()]));

            store.insert(
                &dest.as_key(id, proto as u8),
                to_rule_store(&*port_ranges)
                    .expect("Incorrect number of rules, should've errored in the previous check"),
            )?;

            self.reverse_propagate(store, dest, id, proto)?;
            self.propagate(store, port_range, id, proto)?;
        }
        Ok(())
    }

    fn check_range_len(
        &self,
        port_range: &PortRange<T>,
        id: u128,
        dest: &T,
    ) -> std::result::Result<(), RuleStoreError> {
        if let Some(port_ranges) =
            self.rule_map
                .get(&(id, port_range.ports.proto, Normalized::new(dest.clone())))
        {
            to_rule_store(port_ranges.iter().chain([port_range]))?;
            Ok(())
        } else {
            Ok(())
        }
    }

    fn check_range_len_remove(
        &self,
        port_range: &PortRange<T>,
        id: u128,
        dest: &T,
    ) -> std::result::Result<(), RuleStoreError> {
        if let Some(port_ranges) =
            self.rule_map
                .get(&(id, port_range.ports.proto, Normalized::new(dest.clone())))
        {
            to_rule_store(port_ranges.iter().filter(|p| p != &port_range))?;
            Ok(())
        } else {
            Ok(())
        }
    }
    pub(crate) fn remove_rule(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        RuleImpl {
            id,
            dest,
            port_range,
        }: &RuleImpl<T>,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: port_range.clone().unwrap_or_default(),
            origin: dest.clone(),
        };

        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);
            self.check_range_len_remove(&port_range, id, dest)?;
            self.propagate_removal_check(&port_range, proto, id)?;
        }

        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);
            if let std::collections::hash_map::Entry::Occupied(_) = self
                .rule_map
                .entry((id, proto, Normalized::new(dest.clone())))
                .and_modify(|e| {
                    e.remove(&port_range);
                })
            {
                self.propagate_removal(store, port_range, proto, id)?;
            }

            self.rule_map.retain(|_, v| !v.is_empty());
        }
        Ok(())
    }

    fn propagate_removal_check(
        &mut self,
        port_range: &PortRange<T>,
        proto: Protocol,
        id: u128,
    ) -> Result<()> {
        for (_, v) in self.rule_map.iter().filter(|((k_id, k_proto, k_ip), _)| {
            *k_id == id && *k_proto == proto && port_range.origin.contains(&k_ip.ip)
        }) {
            let mut v = v.clone();
            v.remove(port_range);
            if !v.is_empty() {
                to_rule_store(&v)?;
            }
        }
        Ok(())
    }

    fn propagate_removal(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        port_range: PortRange<T>,
        proto: Protocol,
        id: u128,
    ) -> Result<()> {
        for ((k_id, k_proto, k_ip), v) in
            self.rule_map
                .iter_mut()
                .filter(|((k_id, k_proto, k_ip), _)| {
                    *k_id == id && *k_proto == proto && port_range.origin.contains(&k_ip.ip)
                })
        {
            v.remove(&port_range);
            if !v.is_empty() {
                store.insert(
                    &k_ip.ip.as_key(*k_id, *k_proto as u8),
                    to_rule_store(&*v).expect("Should error on check before"),
                )?;
            } else {
                store.remove(&k_ip.ip.as_key(*k_id, *k_proto as u8))?;
            }
        }
        Ok(())
    }

    fn propagate(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        port_range: PortRange<T>,
        id: u128,
        proto: Protocol,
    ) -> Result<()> {
        self.propagate_impl(store, port_range, id, proto, Method::Modify)
    }

    fn propagate_check(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        port_range: PortRange<T>,
        id: u128,
        proto: Protocol,
    ) -> Result<()> {
        self.propagate_impl(store, port_range, id, proto, Method::Check)
    }

    fn propagate_impl(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        port_range: PortRange<T>,
        id: u128,
        proto: Protocol,
        method: Method,
    ) -> Result<()> {
        for ((k_id, k_proto, k_ip), v) in
            self.rule_map
                .iter_mut()
                .filter(|((k_id, k_proto, k_ip), _)| {
                    *k_id == id && *k_proto == proto && port_range.origin.contains(&k_ip.ip)
                })
        {
            match method {
                Method::Check => {
                    let port_ranges = v.iter().chain([&port_range]);
                    to_rule_store(port_ranges)?;
                }
                Method::Modify => {
                    v.insert(port_range.clone());
                    store.insert(
                        &k_ip.ip.as_key(*k_id, *k_proto as u8),
                        to_rule_store(&*v).expect("Should error on check"),
                    )?;
                }
            }
        }

        Ok(())
    }

    fn reverse_propagate(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        cidr: &T,
        id: u128,
        proto: Protocol,
    ) -> Result<()> {
        self.reverse_propagate_impl(store, cidr, id, proto, Method::Modify)
    }

    fn reverse_propagate_check(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        cidr: &T,
        id: u128,
        proto: Protocol,
    ) -> Result<()> {
        self.reverse_propagate_impl(store, cidr, id, proto, Method::Modify)
    }

    fn reverse_propagate_impl(
        &mut self,
        store: &mut impl BpfStore<K = Key<T::KeySize>, V = RuleStore>,
        cidr: &T,
        id: u128,
        proto: Protocol,
        method: Method,
    ) -> Result<()> {
        let overlapping_parents = self.get_overlapping_parents(cidr, id, proto);
        if let Some(port_ranges) =
            self.rule_map
                .get_mut(&(id, proto, Normalized::new(cidr.clone())))
        {
            match method {
                Method::Check => {
                    to_rule_store(port_ranges.union(&overlapping_parents))?;
                }
                Method::Modify => {
                    port_ranges.extend(overlapping_parents);

                    store.insert(
                        &cidr.as_key(id, proto as u8),
                        to_rule_store(&*port_ranges).expect("Should error on check"),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn get_overlapping_parents(
        &self,
        cidr: &T,
        id: u128,
        proto: Protocol,
    ) -> HashSet<PortRange<T>> {
        self.rule_map
            .iter()
            .filter(|((k_id, k_proto, k_ip), _)| {
                *k_id == id && *k_proto == proto && k_ip.ip.contains(cidr)
            })
            .flat_map(|(_, v)| v)
            .cloned()
            .collect()
    }
}

enum Method {
    Check,
    Modify,
}

fn port_range_check(port_range: &Option<rule::PortRange>) -> bool {
    match port_range {
        Some(range) => range.valid_range(),
        None => true,
    }
}
