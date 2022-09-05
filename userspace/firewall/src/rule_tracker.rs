use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use aya::{
    maps::{lpm_trie::LpmTrie, MapRefMut},
    Bpf,
};
use firewall_common::{Action, ActionStore};

use crate::{
    as_octet::AsOctets,
    cidr::{AsKey, AsNum, Cidr},
    Error, Protocol, Result, ACTION_MAP_IPV4, ACTION_MAP_IPV6,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortRange<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    pub ports: RangeInclusive<u16>,
    pub action: Action,
    pub origin: Cidr<T>,
    pub priority: u32,
    pub proto: Protocol,
}

fn to_action_store<T>(port_ranges: HashSet<PortRange<T>>) -> ActionStore
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    let port_ranges = &mut port_ranges.iter().collect::<Vec<_>>()[..];
    resolve_overlap(port_ranges);

    let mut action_store = ActionStore::default();
    for range in port_ranges {
        action_store
            .add(
                *range.ports.start(),
                *range.ports.end(),
                range.action,
                range.proto as u8,
            )
            .unwrap();
    }
    action_store
}

// This is not optimal, but the way we are resolving overlaps here is:
// We sort by prefix, this makes More specific to less specific
// Then the ebpf search linearly for any match and use the first.
// Effectively prioritizing the greatest prefix, meaning more specificity.
fn resolve_overlap<T>(port_ranges: &mut [&PortRange<T>])
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    port_ranges.sort_by_key(|p| {
        (
            p.origin.prefix(),
            !p.ports.contains(&0),
            p.priority,
            usize::MAX - p.ports.len(),
        )
    });
    port_ranges.reverse();
}

pub struct RuleTracker<T>
where
    T: AsNum + From<T::Num>,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    rule_map: HashMap<(u32, Cidr<T>), HashSet<PortRange<T>>>,
    ebpf_store: LpmTrie<MapRefMut, <Cidr<T> as AsKey>::KeySize, ActionStore>,
}

impl<T> Debug for RuleTracker<T>
where
    T: AsNum + From<T::Num> + Debug,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleTracker")
            .field("rule_map", &self.rule_map)
            .finish()
    }
}

impl RuleTracker<Ipv4Addr> {
    pub fn new_ipv4(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, ACTION_MAP_IPV4)
    }
}

impl RuleTracker<Ipv6Addr> {
    pub fn new_ipv6(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, ACTION_MAP_IPV6)
    }
}

impl<T> RuleTracker<T>
where
    T: AsNum + From<T::Num> + Eq + Hash + Clone,
    Cidr<T>: AsKey,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn new_with_name(bpf: &Bpf, store_name: impl AsRef<str>) -> Result<Self> {
        let ebpf_store: LpmTrie<_, <Cidr<T> as AsKey>::KeySize, ActionStore> =
            LpmTrie::try_from(bpf.map_mut(store_name.as_ref())?)?;
        Ok(Self {
            rule_map: HashMap::new(),
            ebpf_store,
        })
    }

    pub fn add_rule(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>>,
        action: Action,
        priority: u32,
        proto: Protocol,
    ) -> Result<()> {
        let ports = ports.into();
        if ports.contains(&0) && ports.len() > 1 {
            return Err(Error::InvalidPort);
        }
        let port_range = PortRange {
            ports,
            action,
            origin: cidr.clone(),
            priority,
            proto,
        };

        let port_ranges = self
            .rule_map
            .entry((id, cidr.clone()))
            .and_modify(|e| {
                e.insert(port_range.clone());
            })
            .or_insert_with(|| HashSet::from([port_range.clone()]));

        self.ebpf_store
            .insert(&cidr.as_key(id), to_action_store(port_ranges.clone()), 0)?;

        self.reverse_propagate(&cidr, id)?;
        self.propagate(port_range, id)?;
        Ok(())
    }

    pub fn remove_rule(
        &mut self,
        id: u32,
        cidr: Cidr<T>,
        ports: impl Into<RangeInclusive<u16>>,
        action: Action,
        priority: u32,
        proto: Protocol,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: ports.into(),
            action,
            origin: cidr.clone(),
            priority,
            proto,
        };
        if let std::collections::hash_map::Entry::Occupied(_) =
            self.rule_map.entry((id, cidr)).and_modify(|e| {
                e.remove(&port_range);
            })
        {
            self.propagate_removal(port_range, id)?;
        }

        Ok(())
    }

    fn propagate_removal(&mut self, port_range: PortRange<T>, id: u32) -> Result<()> {
        for ((k_id, k_ip), v) in self
            .rule_map
            .iter_mut()
            .filter(|((k_id, k_ip), _)| *k_id == id && port_range.origin.contains(k_ip))
        {
            v.remove(&port_range);
            if !v.is_empty() {
                self.ebpf_store
                    .insert(&k_ip.as_key(*k_id), to_action_store(v.clone()), 0)?;
            } else {
                self.ebpf_store.remove(&k_ip.as_key(*k_id))?;
            }
        }
        Ok(())
    }

    fn propagate(&mut self, port_range: PortRange<T>, id: u32) -> Result<()> {
        for ((k_id, k_ip), v) in self
            .rule_map
            .iter_mut()
            .filter(|((k_id, k_ip), _)| *k_id == id && port_range.origin.contains(k_ip))
        {
            v.insert(port_range.clone());
            self.ebpf_store
                .insert(&k_ip.as_key(*k_id), to_action_store(v.clone()), 0)?;
        }
        Ok(())
    }

    fn reverse_propagate(&mut self, cidr: &Cidr<T>, id: u32) -> Result<()> {
        let propagated_ranges: HashSet<_> = self
            .rule_map
            .iter()
            .filter(|((k_id, k_ip), _)| *k_id == id && k_ip.contains(cidr))
            .flat_map(|(_, v)| v)
            .cloned()
            .collect();
        if let Some(port_ranges) = self.rule_map.get_mut(&(id, cidr.clone())) {
            port_ranges.extend(propagated_ranges);

            self.ebpf_store
                .insert(&cidr.as_key(id), to_action_store(port_ranges.clone()), 0)?;
        }
        Ok(())
    }
}
