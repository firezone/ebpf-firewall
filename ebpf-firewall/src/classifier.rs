use std::net::Ipv4Addr;

use anyhow::Result;
use aya::{
    maps::{HashMap, MapRefMut},
    Bpf,
};

use crate::CLASSIFIER_MAP;

pub struct Classifier {
    ebpf_map: HashMap<MapRefMut, [u8; 4], u32>,
}

impl Classifier {
    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, CLASSIFIER_MAP)
    }

    fn new_with_name(bpf: &Bpf, map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            ebpf_map: HashMap::try_from(bpf.map_mut(map_name.as_ref())?)?,
        })
    }

    pub fn insert(&mut self, ip: Ipv4Addr, id: u32) -> Result<()> {
        self.ebpf_map.insert(ip.octets(), id, 0)?;
        Ok(())
    }
}
