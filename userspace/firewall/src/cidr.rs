use std::{
    net::{Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, Not, Shr},
};

use aya::{maps::lpm_trie::Key, Pod};

use crate::as_octet::AsOctets;

pub type Ipv4CIDR = Cidr<Ipv4Addr>;
pub type Ipv6CIDR = Cidr<Ipv6Addr>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    ip: T,
    prefix: u8,
}

pub trait AsNum {
    type Num: BitAnd<Output = Self::Num>
        + CheckedShr
        + Shr<u8>
        + Not<Output = Self::Num>
        + Default
        + PartialEq;
    fn as_num(&self) -> Self::Num;
    fn max() -> Self::Num;
}

pub trait CheckedShr
where
    Self: Sized,
{
    fn checked_shr(self, rhs: u32) -> Option<Self>;
}

impl CheckedShr for u32 {
    fn checked_shr(self, rhs: u32) -> Option<Self> {
        u32::checked_shr(self, rhs)
    }
}

impl CheckedShr for u128 {
    fn checked_shr(self, rhs: u32) -> Option<Self> {
        u128::checked_shr(self, rhs)
    }
}

impl AsNum for Ipv4Addr {
    type Num = u32;

    fn as_num(&self) -> Self::Num {
        u32::from(*self)
    }

    fn max() -> Self::Num {
        u32::MAX
    }
}

impl AsNum for Ipv6Addr {
    type Num = u128;

    fn as_num(&self) -> Self::Num {
        u128::from(*self)
    }

    fn max() -> Self::Num {
        u128::MAX
    }
}

impl<T> Cidr<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    // TODO check for valid prefix
    pub fn new(ip: T, prefix: u8) -> Self {
        Self {
            ip: Self::normalize(ip, prefix),
            prefix,
        }
    }

    pub(crate) fn prefix(&self) -> u8 {
        self.prefix
    }

    fn normalize(ip: T, prefix: u8) -> T {
        T::from(ip.as_num() & Self::mask_prefix(prefix))
    }

    fn mask(&self) -> T::Num {
        Self::mask_prefix(self.prefix)
    }

    fn mask_prefix(prefix: u8) -> T::Num {
        !(T::max().checked_shr(prefix.into()).unwrap_or_default())
    }

    pub(crate) fn contains(&self, k: &Cidr<T>) -> bool {
        k.prefix >= self.prefix
            && ((self.ip.as_num() & self.mask()) == (k.ip.as_num() & self.mask()))
    }

    fn key<const N: usize>(&self, id: u32) -> Key<[u8; N]> {
        let key_id = id.to_be_bytes();
        let key_cidr = self.ip.as_octets();
        let mut key_data = [0u8; N];
        let (id, cidr) = key_data.split_at_mut(4);
        id.copy_from_slice(&key_id);
        cidr.copy_from_slice(key_cidr.as_ref());
        Key::new(u32::from(self.prefix) + 32, key_data)
    }
}

pub trait AsKey {
    type KeySize: Pod;
    fn as_key(&self, id: u32) -> Key<Self::KeySize>;
}

impl AsKey for Cidr<Ipv4Addr> {
    type KeySize = [u8; 8];
    fn as_key(&self, id: u32) -> Key<Self::KeySize> {
        self.key(id)
    }
}

impl AsKey for Cidr<Ipv6Addr> {
    type KeySize = [u8; 20];
    fn as_key(&self, id: u32) -> Key<Self::KeySize> {
        self.key(id)
    }
}
