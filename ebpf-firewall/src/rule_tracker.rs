use anyhow::Result;
use std::{collections::HashMap, net::Ipv4Addr};

use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        MapRefMut,
    },
    Bpf,
};
use ebpf_firewall_common::ActionStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CIDR {
    ip: Ipv4Addr,
    prefix: u8,
}

impl CIDR {
    // TODO check for valid prefix
    pub(crate) fn new(ip: Ipv4Addr, prefix: u8) -> Self {
        Self { ip, prefix }
    }
}

#[derive(Debug, Clone, Copy)]
struct PortRange {
    pub start: u16,
    pub end: u16,
    pub action: bool,
    pub origin: CIDR,
}

fn to_action_store(port_ranges: Vec<PortRange>) -> ActionStore {
    let mut action_store = ActionStore::new();
    for range in port_ranges {
        // TODO
        action_store
            .add(range.start, range.end, range.action)
            .unwrap();
    }
    action_store
}

pub(crate) struct RuleTracker {
    rule_map: HashMap<(u32, CIDR), Vec<PortRange>>,
    ebpf_store: LpmTrie<MapRefMut, [u8; 8], ActionStore>,
}

impl RuleTracker {
    pub(crate) fn new(bpf: &Bpf, store_name: impl AsRef<str>) -> Result<Self> {
        let ebpf_store: LpmTrie<_, [u8; 8], ActionStore> =
            LpmTrie::try_from(bpf.map_mut(store_name.as_ref())?)?;
        Ok(Self {
            rule_map: HashMap::new(),
            ebpf_store,
        })
    }

    pub(crate) fn add_rule(
        &mut self,
        id: u32,
        cidr: CIDR,
        port_start: u16,
        port_end: u16,
        action: bool,
    ) -> Result<()> {
        let port_range = PortRange {
            start: port_start,
            end: port_end,
            action,
            origin: cidr,
        };

        let port_ranges = self
            .rule_map
            .entry((id, cidr))
            .and_modify(|e| e.push(port_range.clone()))
            .or_insert(vec![port_range.clone()]);

        self.ebpf_store
            .insert(&cidr.get_key(id), to_action_store(port_ranges.clone()), 0)?;

        self.propagate(port_range, id)
    }

    fn propagate(&mut self, port_range: PortRange, id: u32) -> Result<()> {
        for ((k_id, k_ip), v) in self.rule_map.iter_mut() {
            if *k_id == id && port_range.origin.contains(k_ip) {
                v.push(port_range);
                self.ebpf_store
                    .insert(&k_ip.get_key(*k_id), to_action_store(v.clone()), 0)?;
            }
        }
        Ok(())
    }
}

impl CIDR {
    fn contains(&self, k: &CIDR) -> bool {
        k.prefix > self.prefix
            && (self.mask() & u32::from(self.ip) == self.mask() & u32::from(k.ip))
    }
    fn mask(&self) -> u32 {
        !(u32::MAX >> self.prefix)
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
