use aya::{
    maps::{HashMap, MapRefMut},
    Bpf, Pod,
};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{as_octet::AsOctets, Error, Result, SOURCE_ID_IPV4, SOURCE_ID_IPV6};

pub struct Classifier<T: AsOctets>
where
    T::Octets: Pod,
{
    ebpf_map: HashMap<MapRefMut, T::Octets, u32>,
}

pub(crate) type ClassifierV6 = Classifier<Ipv6Net>;
pub(crate) type ClassifierV4 = Classifier<Ipv4Net>;

impl Classifier<Ipv4Net> {
    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, SOURCE_ID_IPV4)
    }
}

impl Classifier<Ipv6Net> {
    pub fn new(bpf: &Bpf) -> Result<Self> {
        Self::new_with_name(bpf, SOURCE_ID_IPV6)
    }
}

impl<T: AsOctets> Classifier<T>
where
    T::Octets: Pod,
{
    pub fn insert(&mut self, ip: T, id: u32) -> Result<()> {
        if id == 0 {
            return Err(Error::InvalidId);
        }
        self.ebpf_map.insert(ip.as_octets(), id, 0)?;
        Ok(())
    }

    pub fn remove(&mut self, ip: &T) -> Result<()> {
        self.ebpf_map.remove(&ip.as_octets())?;
        Ok(())
    }

    fn new_with_name(bpf: &Bpf, map_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            ebpf_map: HashMap::try_from(bpf.map_mut(map_name.as_ref())?)?,
        })
    }
}
