use std::{collections::HashSet, hash::Hash};

use aya::Pod;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{as_octet::AsOctets, bpf_store::BpfStore, Error, Result};

type ID = [u8; 16];

#[derive(Debug)]
pub struct Classifier<T: AsOctets>
where
    T::Octets: Pod + Eq + Hash,
{
    userland_map: std::collections::HashMap<u128, HashSet<T::Octets>>,
}

pub(crate) type ClassifierV6 = Classifier<Ipv6Net>;
pub(crate) type ClassifierV4 = Classifier<Ipv4Net>;

impl<T: AsOctets> Classifier<T>
where
    T::Octets: Pod + Eq + Hash,
{
    pub fn new() -> Result<Self> {
        Ok(Self {
            userland_map: Default::default(),
        })
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
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::ClassifierV4;
    use crate::{
        as_octet::AsOctets, bpf_store::test_store::HashTestStore, classifier::ClassifierV6,
    };

    #[test]
    fn insert_v4() {
        let mut classifier = ClassifierV4::new().expect("Couldn't get classifier");
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, "10.0.0.1/32".parse().unwrap(), 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert([10, 0, 0, 1]);
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
    }

    #[test]
    fn insert_v6() {
        let mut classifier = ClassifierV6::new().expect("Couldn't get classifier");
        let ip = "fe80::1/128".parse().unwrap();
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, ip, 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert(ip.as_octets());
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
    }

    #[test]
    fn remove_v4() {
        let mut classifier = ClassifierV4::new().expect("Couldn't get classifier");
        let ip = "10.0.0.1/32".parse().unwrap();
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, ip, 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert(ip.as_octets());
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
        classifier
            .remove(&mut store, &ip)
            .expect("Couldn't insert into store");
        assert_eq!(classifier.userland_map.get(&1u128), None);
    }

    #[test]
    fn remove_v6() {
        let mut classifier = ClassifierV6::new().expect("Couldn't get classifier");
        let ip = "fe80::1/128".parse().unwrap();
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, ip, 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert(ip.as_octets());
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
        classifier
            .remove(&mut store, &ip)
            .expect("Couldn't insert into store");
        assert_eq!(classifier.userland_map.get(&1u128), None);
    }

    #[test]
    fn remove_v4_by_id() {
        let mut classifier = ClassifierV4::new().expect("Couldn't get classifier");
        let ip = "10.0.0.1/32".parse().unwrap();
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, ip, 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert(ip.as_octets());
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
        classifier
            .remove_by_id(&mut store, 1u128)
            .expect("Couldn't insert into store");
        assert_eq!(classifier.userland_map.get(&1u128), None);
    }

    #[test]
    fn remove_v6_by_id() {
        let mut classifier = ClassifierV6::new().expect("Couldn't get classifier");
        let ip = "fe80::1/128".parse().unwrap();
        let mut store = HashTestStore::new();
        classifier
            .insert(&mut store, ip, 1u128)
            .expect("Couldn't insert into store");
        let mut res = HashSet::new();
        res.insert(ip.as_octets());
        assert_eq!(classifier.userland_map.get(&1u128), Some(&res));
        classifier
            .remove_by_id(&mut store, 1u128)
            .expect("Couldn't insert into store");
        assert_eq!(classifier.userland_map.get(&1u128), None);
    }
}
