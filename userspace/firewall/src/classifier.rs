use std::{collections::HashSet, hash::Hash};

use aya::Pod;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{as_octet::AsOctets, bpf_store::BpfStore, Error, Result};

type ID = [u8; 16];

pub struct Classifier<T: AsOctets>
where
    T::Octets: Pod + Eq + Hash,
{
    userland_map: std::collections::HashMap<u128, HashSet<T::Octets>>,
}

pub(crate) type ClassifierV6 = Classifier<Ipv6Net>;
pub(crate) type ClassifierV4 = Classifier<Ipv4Net>;

impl Classifier<Ipv4Net> {
    pub fn new() -> Result<Self> {
        Self::new_with_name()
    }
}

impl Classifier<Ipv6Net> {
    pub fn new() -> Result<Self> {
        Self::new_with_name()
    }
}

impl<T: AsOctets> Classifier<T>
where
    T::Octets: Pod + Hash + Eq,
{
    pub fn insert(
        &mut self,
        store: &mut impl BpfStore<K = T::Octets, V = ID>,
        ip: T,
        id: u128,
    ) -> Result<()> {
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
        store.insert(&ip.as_octets(), id.to_le_bytes())?;
        Ok(())
    }

    pub fn remove(
        &mut self,
        store: &mut impl BpfStore<K = T::Octets, V = ID>,
        ip: &T,
    ) -> Result<()> {
        let id = u128::from_le_bytes(store.get(&ip.as_octets())?);
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

    pub fn remove_by_id(
        &mut self,
        store: &mut impl BpfStore<K = T::Octets, V = ID>,
        id: u128,
    ) -> Result<()> {
        let ips = self.userland_map.get(&id).ok_or(Error::NotExistingId)?;
        for ip in ips {
            store.remove(ip)?;
        }
        self.userland_map.remove(&id);
        Ok(())
    }

    fn new_with_name() -> Result<Self> {
        Ok(Self {
            userland_map: Default::default(),
        })
    }
}
