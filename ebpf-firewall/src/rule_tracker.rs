use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    net::Ipv4Addr,
    ops::RangeInclusive,
};

use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        MapRefMut,
    },
    Bpf,
};
use ebpf_firewall_common::ActionStore;

use crate::ACTION_MAP_IPV4;
use crate::{Protocol, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CIDR {
    ip: Ipv4Addr,
    prefix: u8,
}

impl CIDR {
    // TODO check for valid prefix
    pub fn new(ip: Ipv4Addr, prefix: u8) -> Self {
        Self { ip, prefix }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PortRange {
    pub ports: RangeInclusive<u16>,
    pub action: bool,
    pub origin: CIDR,
    pub priority: u32,
    pub proto: Protocol,
}

fn to_action_store(port_ranges: HashSet<PortRange>) -> ActionStore {
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
fn resolve_overlap(port_ranges: &mut [&PortRange]) {
    port_ranges.sort_by_key(|p| (p.origin.prefix, p.priority, usize::MAX - p.ports.len()));
    port_ranges.reverse();
}

pub struct RuleTracker {
    rule_map: HashMap<(u32, CIDR), HashSet<PortRange>>,
    ebpf_store: LpmTrie<MapRefMut, [u8; 8], ActionStore>,
}

impl Debug for RuleTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleTracker")
            .field("rule_map", &self.rule_map)
            .finish()
    }
}

impl RuleTracker {
    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, ACTION_MAP_IPV4)
    }

    fn new_with_name(bpf: &Bpf, store_name: impl AsRef<str>) -> Result<Self> {
        let ebpf_store: LpmTrie<_, [u8; 8], ActionStore> =
            LpmTrie::try_from(bpf.map_mut(store_name.as_ref())?)?;
        Ok(Self {
            rule_map: HashMap::new(),
            ebpf_store,
        })
    }

    pub fn add_rule(
        &mut self,
        id: u32,
        cidr: CIDR,
        ports: impl Into<RangeInclusive<u16>>,
        action: bool,
        priority: u32,
        proto: Protocol,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: ports.into(),
            action,
            origin: cidr,
            priority,
            proto,
        };

        let port_ranges = self
            .rule_map
            .entry((id, cidr))
            .and_modify(|e| {
                e.insert(port_range.clone());
            })
            .or_insert_with(|| HashSet::from([port_range.clone()]));

        self.ebpf_store
            .insert(&cidr.get_key(id), to_action_store(port_ranges.clone()), 0)?;

        self.reverse_propagate(&cidr, id)?;
        self.propagate(port_range, id)?;
        Ok(())
    }

    pub fn remove_rule(
        &mut self,
        id: u32,
        cidr: CIDR,
        ports: impl Into<RangeInclusive<u16>>,
        action: bool,
        priority: u32,
        proto: Protocol,
    ) -> Result<()> {
        let port_range = PortRange {
            ports: ports.into(),
            action,
            origin: cidr,
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

    fn propagate_removal(&mut self, port_range: PortRange, id: u32) -> Result<()> {
        for ((k_id, k_ip), v) in self
            .rule_map
            .iter_mut()
            .filter(|((k_id, k_ip), _)| *k_id == id && port_range.origin.contains(k_ip))
        {
            v.remove(&port_range);
            if !v.is_empty() {
                self.ebpf_store
                    .insert(&k_ip.get_key(*k_id), to_action_store(v.clone()), 0)?;
            } else {
                self.ebpf_store.remove(&k_ip.get_key(*k_id))?;
            }
        }
        Ok(())
    }

    fn propagate(&mut self, port_range: PortRange, id: u32) -> Result<()> {
        for ((k_id, k_ip), v) in self
            .rule_map
            .iter_mut()
            .filter(|((k_id, k_ip), _)| *k_id == id && port_range.origin.contains(k_ip))
        {
            v.insert(port_range.clone());
            self.ebpf_store
                .insert(&k_ip.get_key(*k_id), to_action_store(v.clone()), 0)?;
        }
        Ok(())
    }

    fn reverse_propagate(&mut self, cidr: &CIDR, id: u32) -> Result<()> {
        let propagated_ranges: HashSet<_> = self
            .rule_map
            .iter()
            .filter(|((k_id, k_ip), _)| *k_id == id && k_ip.contains(cidr))
            .flat_map(|(_, v)| v)
            .cloned()
            .collect();
        if let Some(port_ranges) = self.rule_map.get_mut(&(id, *cidr)) {
            port_ranges.extend(propagated_ranges);

            self.ebpf_store
                .insert(&cidr.get_key(id), to_action_store(port_ranges.clone()), 0)?;
        }
        Ok(())
    }
}

impl CIDR {
    fn contains(&self, k: &CIDR) -> bool {
        k.prefix >= self.prefix
            && (self.mask() & u32::from(self.ip) == self.mask() & u32::from(k.ip))
    }

    fn mask(&self) -> u32 {
        !(u32::MAX.checked_shr(self.prefix.into()).unwrap_or(0))
    }

    fn get_key(&self, id: u32) -> Key<[u8; 8]> {
        let key_id = id.to_be_bytes();
        let key_cidr = self.ip.octets();
        let mut key_data = [0u8; 8];
        let (id, cidr) = key_data.split_at_mut(4);
        id.copy_from_slice(&key_id);
        cidr.copy_from_slice(&key_cidr);
        Key::new(u32::from(self.prefix) + 32, key_data)
    }
}
