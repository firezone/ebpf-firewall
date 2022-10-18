mod rule_trie;
mod test;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
};

use aya::{
    maps::{lpm_trie::LpmTrie, MapRefMut},
    Bpf,
};
use firewall_common::RuleStore;

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Cidr},
    Error, Protocol, Result, Rule, RULE_MAP_IPV4, RULE_MAP_IPV6,
};
use rule_trie::RuleTrie;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortRange<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    pub ports: super::PortRange,
    pub origin: Cidr<T>,
}

impl<T> PortRange<T>
where
    T: AsNum + From<T::Num> + AsOctets + Clone,
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

pub type RuleTrackerV4 = RuleTracker<Ipv4Addr, LpmTrie<MapRefMut, [u8; 9], RuleStore>>;
pub type RuleTrackerV6 = RuleTracker<Ipv6Addr, LpmTrie<MapRefMut, [u8; 21], RuleStore>>;

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
    pub fn new_ipv4(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, RULE_MAP_IPV4)
    }
}

impl RuleTracker<Ipv6Addr, LpmTrie<MapRefMut, [u8; 21], RuleStore>> {
    pub fn new_ipv6(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, RULE_MAP_IPV6)
    }
}

impl<T> RuleTracker<T, LpmTrie<MapRefMut, <Cidr<T> as AsKey>::KeySize, RuleStore>>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn new_with_name(bpf: &Bpf, store_name: impl AsRef<str>) -> Result<Self> {
        let ebpf_store: LpmTrie<_, <Cidr<T> as AsKey>::KeySize, RuleStore> =
            LpmTrie::try_from(bpf.map_mut(store_name.as_ref())?)?;
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
        Rule {
            id,
            dest,
            port_range,
        }: &Rule<T>,
    ) -> Result<()> {
        if !port_range_check(port_range) {
            return Err(Error::InvalidPort);
        }

        let port_range = PortRange {
            ports: port_range.clone().unwrap_or_default(),
            origin: dest.clone(),
        };

        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);

            let port_ranges = self
                .rule_map
                .entry((id, port_range.ports.proto, dest.clone()))
                .and_modify(|e| {
                    e.insert(port_range.clone());
                })
                .or_insert_with(|| HashSet::from([port_range.clone()]));

            self.ebpf_store.insert(
                &dest.as_key(id, proto as u8),
                to_rule_store(port_ranges.clone()),
            )?;

            self.reverse_propagate(&dest, id, proto)?;
            self.propagate(port_range, id, proto)?;
        }
        Ok(())
    }

    pub fn remove_rule(
        &mut self,
        Rule {
            id,
            dest,
            port_range,
        }: &Rule<T>,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: port_range.clone().unwrap_or_default(),
            origin: dest.clone(),
        };

        for port_range in port_range.unfold() {
            let proto = port_range.ports.proto;
            let id = id.unwrap_or(0);
            if let std::collections::hash_map::Entry::Occupied(_) = self
                .rule_map
                .entry((id, proto, dest.clone()))
                .and_modify(|e| {
                    e.remove(&port_range);
                })
            {
                self.propagate_removal(port_range, proto, id)?;
            }
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

fn port_range_check(port_range: &Option<super::PortRange>) -> bool {
    match port_range {
        Some(range) => range.valid_range(),
        None => true,
    }
}
