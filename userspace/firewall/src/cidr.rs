use std::{
    fmt::Debug,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    ops::{BitAnd, Not, Shr},
    str::FromStr,
};

use aya::{maps::lpm_trie::Key, Pod};
use thiserror::Error;

use crate::as_octet::AsOctets;

pub type Ipv4CIDR = Cidr<Ipv4Addr>;
pub type Ipv6CIDR = Cidr<Ipv6Addr>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    ip: T,
    prefix: u8,
}

impl<T> Debug for Cidr<T>
where
    T: AsNum + From<T::Num> + Debug,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{:?}", self.ip, self.prefix)
    }
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CidrParseError {
    #[error("Invalid CIDR format")]
    InvalidFormat,
    #[error("Invalid address format")]
    IpError(#[from] AddrParseError),
    #[error("Invalid prefix format")]
    PrefixError(#[from] ParseIntError),
}

impl<T> FromStr for Cidr<T>
where
    T: AsNum + From<T::Num>,
    T: AsOctets,
    T::Octets: AsRef<[u8]>,
    T: FromStr<Err = AddrParseError>,
{
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let try_cidr: Vec<&str> = s.split('/').collect();
        if try_cidr.len() != 2 {
            return Err(CidrParseError::InvalidFormat);
        }

        Ok(Self {
            // We can unwrap here because we just checked try_cidr.len() == 2
            ip: try_cidr.get(0).unwrap().parse()?,
            // We can unwrap here because we just checked try_cidr.len() == 2
            prefix: try_cidr.get(1).unwrap().parse()?,
        })
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

    fn key<const N: usize>(&self, id: u32, proto: u8) -> Key<[u8; N]> {
        let key_id = id.to_be_bytes();
        let key_cidr = self.ip.as_octets();
        let mut key_data = [0u8; N];
        let (left_key_data, cidr) = key_data.split_at_mut(5);
        let (id, prot) = left_key_data.split_at_mut(4);
        prot[0] = proto;
        id.copy_from_slice(&key_id);
        cidr.copy_from_slice(key_cidr.as_ref());
        Key::new(u32::from(self.prefix) + 32, key_data)
    }
}

pub trait AsKey {
    type KeySize: Pod;
    fn as_key(&self, id: u32, proto: u8) -> Key<Self::KeySize>;
}

impl AsKey for Cidr<Ipv4Addr> {
    type KeySize = [u8; 9];
    fn as_key(&self, id: u32, proto: u8) -> Key<Self::KeySize> {
        self.key(id, proto)
    }
}

impl AsKey for Cidr<Ipv6Addr> {
    type KeySize = [u8; 21];
    fn as_key(&self, id: u32, proto: u8) -> Key<Self::KeySize> {
        self.key(id, proto)
    }
}

#[cfg(test)]
mod test {
    use std::{net::Ipv6Addr, str::FromStr};

    use crate::Ipv6CIDR;

    #[test]
    fn contains_works_v6() {
        let cidr_64 = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::").unwrap(), 64);
        let cidr_96 = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:0").unwrap(), 96);
        let cidr_128 = Ipv6CIDR::new(Ipv6Addr::from_str("fafa::1:0:0:3").unwrap(), 128);
        assert!(cidr_64.contains(&cidr_64));
        assert!(cidr_64.contains(&cidr_96));
        assert!(cidr_64.contains(&cidr_128));
        assert!(!cidr_96.contains(&cidr_64));
        assert!(cidr_96.contains(&cidr_96));
        assert!(cidr_96.contains(&cidr_128));
        assert!(!cidr_128.contains(&cidr_64));
        assert!(!cidr_128.contains(&cidr_96));
        assert!(cidr_128.contains(&cidr_128));
    }
}
