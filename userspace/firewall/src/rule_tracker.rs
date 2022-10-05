mod rule_trie;
mod test;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use aya::maps::{lpm_trie::LpmTrie, MapRefMut};
use firewall_common::RuleStore;

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Cidr},
    Error, Program, Protocol, Result, RULE_MAP_IPV4, RULE_MAP_IPV6,
};
use rule_trie::RuleTrie;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortRange<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    pub ports: RangeInclusive<u16>,
    pub origin: Cidr<T>,
}

fn to_rule_store<T>(port_ranges: HashSet<PortRange<T>>) -> RuleStore
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    let port_ranges = &mut port_ranges.iter().collect::<Vec<_>>()[..];

    // TODO: Handle rule exhaustion
    RuleStore::new(&resolve_overlap(port_ranges)).unwrap()
}

fn resolve_overlap<T>(port_ranges: &mut [&PortRange<T>]) -> Vec<(u16, u16)>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    let mut res = Vec::new();
    port_ranges.sort_by_key(|p| p.ports.start());
    if let Some(range) = port_ranges.first() {
        res.push((*range.ports.start(), *range.ports.end()));
    } else {
        return res;
    }
    for range in &port_ranges[1..] {
        let last_res = res
            .last_mut()
            .expect("should contain at least the first element of port_ranges");

        if last_res.1 >= *range.ports.start() {
            *last_res = (last_res.0, last_res.1.max(*range.ports.end()));
        } else {
            res.push((*range.ports.start(), *range.ports.end()));
        }
    }
    res
}

pub struct RuleTracker<T, U>
where
    T: AsNum + From<T::Num>,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
    U: RuleTrie<<Cidr<T> as AsKey>::KeySize, RuleStore>,
{
    rule_map: HashMap<(u32, Protocol, Cidr<T>), HashSet<PortRange<T>>>,
    ebpf_store: U,
}

impl<T, U> Debug for RuleTracker<T, U>
where
    T: AsNum + From<T::Num> + Debug,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
    U: RuleTrie<<Cidr<T> as AsKey>::KeySize, RuleStore>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleTracker")
            .field("rule_map", &self.rule_map)
            .finish()
    }
}

impl RuleTracker<Ipv4Addr, LpmTrie<MapRefMut, [u8; 9], RuleStore>> {
    pub fn new_ipv4(program: &Program) -> Result<Self> {
        Self::new_with_name(program, RULE_MAP_IPV4)
    }
}

impl RuleTracker<Ipv6Addr, LpmTrie<MapRefMut, [u8; 21], RuleStore>> {
    pub fn new_ipv6(program: &Program) -> Result<Self> {
        Self::new_with_name(program, RULE_MAP_IPV6)
    }
}

impl<T> RuleTracker<T, LpmTrie<MapRefMut, <Cidr<T> as AsKey>::KeySize, RuleStore>>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn new_with_name(program: &Program, store_name: impl AsRef<str>) -> Result<Self> {
        let ebpf_store: LpmTrie<_, <Cidr<T> as AsKey>::KeySize, RuleStore> =
            LpmTrie::try_from(program.0.map_mut(store_name.as_ref())?)?;
        Ok(Self {
            rule_map: HashMap::new(),
            ebpf_store,
        })
    }
}

impl<T, U> RuleTracker<T, U>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
    U: RuleTrie<<Cidr<T> as AsKey>::KeySize, RuleStore>,
{
    pub fn add_rule(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>> + Clone,
        proto: Protocol,
    ) -> Result<()> {
        if proto == Protocol::Generic {
            let res = self.add_rule_impl(id, cidr.clone(), ports.clone(), Protocol::TCP);
            if res.is_ok() {
                self.add_rule_impl(id, cidr, ports, Protocol::UDP)
            } else {
                res
            }
        } else {
            self.add_rule_impl(id, cidr, ports, proto)
        }
    }

    fn add_rule_impl(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>> + Clone,
        proto: Protocol,
    ) -> Result<()> {
        let ports = ports.into();
        if ports.contains(&0) && ports.len() > 1 {
            return Err(Error::InvalidPort);
        }
        let port_range = PortRange {
            ports,
            origin: cidr.clone(),
        };

        let port_ranges = self
            .rule_map
            .entry((id, proto, cidr.clone()))
            .and_modify(|e| {
                e.insert(port_range.clone());
            })
            .or_insert_with(|| HashSet::from([port_range.clone()]));

        self.ebpf_store.insert(
            &cidr.as_key(id, proto as u8),
            to_rule_store(port_ranges.clone()),
        )?;

        self.reverse_propagate(&cidr, id, proto)?;
        self.propagate(port_range, id, proto)?;
        Ok(())
    }
    pub fn remove_rule(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>> + Clone,
        proto: Protocol,
    ) -> Result<()> {
        if proto == Protocol::Generic {
            let res = self.remove_rule_impl(id, cidr.clone(), ports.clone(), Protocol::TCP);
            if res.is_ok() {
                self.remove_rule_impl(id, cidr, ports, Protocol::UDP)
            } else {
                res
            }
        } else {
            self.remove_rule_impl(id, cidr, ports, proto)
        }
    }

    pub fn remove_rule_impl(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>> + Clone,
        proto: Protocol,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: ports.into(),
            origin: cidr.clone(),
        };
        if let std::collections::hash_map::Entry::Occupied(_) =
            self.rule_map.entry((id, proto, cidr)).and_modify(|e| {
                e.remove(&port_range);
            })
        {
            self.propagate_removal(port_range, proto, id)?;
        }

        Ok(())
    }

    fn propagate_removal(
        &mut self,
        port_range: PortRange<T>,
        proto: Protocol,
        id: u32,
    ) -> Result<()> {
        for ((k_id, k_proto, k_ip), v) in
            self.rule_map
                .iter_mut()
                .filter(|((k_id, k_proto, k_ip), _)| {
                    *k_id == id && *k_proto == proto && port_range.origin.contains(k_ip)
                })
        {
            v.remove(&port_range);
            if !v.is_empty() {
                self.ebpf_store.insert(
                    &k_ip.as_key(*k_id, *k_proto as u8),
                    to_rule_store(v.clone()),
                )?;
            } else {
                self.ebpf_store
                    .remove(&k_ip.as_key(*k_id, *k_proto as u8))?;
            }
        }
        Ok(())
    }

    fn propagate(&mut self, port_range: PortRange<T>, id: u32, proto: Protocol) -> Result<()> {
        for ((k_id, k_proto, k_ip), v) in
            self.rule_map
                .iter_mut()
                .filter(|((k_id, k_proto, k_ip), _)| {
                    *k_id == id && *k_proto == proto && port_range.origin.contains(k_ip)
                })
        {
            v.insert(port_range.clone());
            self.ebpf_store.insert(
                &k_ip.as_key(*k_id, *k_proto as u8),
                to_rule_store(v.clone()),
            )?;
        }
        Ok(())
    }

    fn reverse_propagate(&mut self, cidr: &Cidr<T>, id: u32, proto: Protocol) -> Result<()> {
        let propagated_ranges: HashSet<_> = self
            .rule_map
            .iter()
            .filter(|((k_id, k_proto, k_ip), _)| {
                *k_id == id && *k_proto == proto && k_ip.contains(cidr)
            })
            .flat_map(|(_, v)| v)
            .cloned()
            .collect();
        if let Some(port_ranges) = self.rule_map.get_mut(&(id, proto, cidr.clone())) {
            port_ranges.extend(propagated_ranges);

            self.ebpf_store.insert(
                &cidr.as_key(id, proto as u8),
                to_rule_store(port_ranges.clone()),
            )?;
        }
        Ok(())
    }
}
