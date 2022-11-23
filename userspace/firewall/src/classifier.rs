use std::{collections::HashSet, hash::Hash};

use aya::{maps::HashMap, maps::MapData, Bpf, Pod};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{as_octet::AsOctets, Error, Result, SOURCE_ID_IPV4, SOURCE_ID_IPV6};

type ID = [u8; 16];

pub struct Classifier<T: AsOctets>
where
    T::Octets: Pod + Eq + Hash,
{
    userland_map: std::collections::HashMap<u128, HashSet<T::Octets>>,
    store_name: String,
}

pub(crate) type ClassifierV6 = Classifier<Ipv6Net>;
pub(crate) type ClassifierV4 = Classifier<Ipv4Net>;

impl Classifier<Ipv4Net> {
    pub fn new() -> Result<Self> {
        Self::new_with_name(SOURCE_ID_IPV4)
    }
}

impl Classifier<Ipv6Net> {
    pub fn new() -> Result<Self> {
        Self::new_with_name(SOURCE_ID_IPV6)
    }
}

impl<T: AsOctets> Classifier<T>
where
    T::Octets: Pod + Hash + Eq,
{
    fn get_store<'a>(&self, bpf: &'a mut Bpf) -> Result<HashMap<&'a mut MapData, T::Octets, ID>> {
        Ok(HashMap::try_from(
            bpf.map_mut(&self.store_name).ok_or(Error::MapNotFound)?,
        )?)
    }
    pub fn insert(&mut self, bpf: &mut Bpf, ip: T, id: u128) -> Result<()> {
        if id == 0 {
            return Err(Error::InvalidId);
        }
        self.userland_map
            .entry(id)
            .and_modify(|e| {
                e.insert(ip.as_octets());
            })
            .or_insert_with(|| {
                let mut set = HashSet::new();
                set.insert(ip.as_octets());
                set
            });
        self.get_store(bpf)?
            .insert(ip.as_octets(), id.to_le_bytes(), 0)?;
        Ok(())
    }

    pub fn remove(&mut self, bpf: &mut Bpf, ip: &T) -> Result<()> {
        let mut store = self.get_store(bpf)?;
        let id = u128::from_le_bytes(store.get(&ip.as_octets(), 0)?);
        self.userland_map
            .get_mut(&id)
            .map(|e| e.remove(&ip.as_octets()));
        if let Some(set) = self.userland_map.get(&id) {
            if set.is_empty() {
                self.userland_map.remove(&id);
            }
        }
        store.remove(&ip.as_octets())?;
        Ok(())
    }

    pub fn remove_by_id(&mut self, bpf: &mut Bpf, id: u128) -> Result<()> {
        let mut store = self.get_store(bpf)?;
        let ips = self.userland_map.get(&id).ok_or(Error::NotExistingId)?;
        for ip in ips {
            store.remove(ip)?;
        }
        self.userland_map.remove(&id);
        Ok(())
    }

    fn new_with_name(map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            userland_map: Default::default(),
            store_name: map_name.as_ref().to_string(),
        })
    }
}
