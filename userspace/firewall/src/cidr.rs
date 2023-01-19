use aya::{maps::lpm_trie::Key, Pod};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::as_octet::AsOctets;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Normalized<T>
where
    T: Normalize,
{
    pub ip: T,
}

impl<T> Normalized<T>
where
    T: Normalize,
{
    pub(crate) fn new(ip: T) -> Self {
        Self { ip: ip.normalize() }
    }
}

pub trait Normalize {
    fn normalize(&self) -> Self;
}

impl Normalize for Ipv4Net {
    fn normalize(&self) -> Self {
        self.trunc()
    }
}

impl Normalize for Ipv6Net {
    fn normalize(&self) -> Self {
        self.trunc()
    }
}

pub trait Contains {
    fn contains(&self, other: &Self) -> bool;
}

impl Contains for Ipv4Net {
    fn contains(&self, other: &Self) -> bool {
        Ipv4Net::contains(self, other)
    }
}

impl Contains for Ipv6Net {
    fn contains(&self, other: &Self) -> bool {
        Ipv6Net::contains(self, other)
    }
}

trait Prefixed {
    fn prefix(&self) -> u8;
}

impl Prefixed for Ipv4Net {
    fn prefix(&self) -> u8 {
        self.prefix_len()
    }
}

impl Prefixed for Ipv6Net {
    fn prefix(&self) -> u8 {
        self.prefix_len()
    }
}

fn key<const N: usize, T>(ip: &T, id: u128, proto: u8) -> Key<[u8; N]>
where
    T: AsOctets + Normalize + Prefixed,
    T::Octets: AsRef<[u8]>,
{
    let key_id = id.to_le_bytes();
    let key_cidr = ip.normalize().as_octets();
    let mut key_data = [0u8; N];
    let (left_key_data, cidr) = key_data.split_at_mut(17);
    let (id, prot) = left_key_data.split_at_mut(16);
    prot[0] = proto;
    id.copy_from_slice(&key_id);
    cidr.copy_from_slice(key_cidr.as_ref());
    Key::new(
        u32::from(ip.prefix()) + (left_key_data.len() * 8) as u32,
        key_data,
    )
}

pub trait AsKey {
    type KeySize: Pod;
    fn as_key(&self, id: u128, proto: u8) -> Key<Self::KeySize>;
}

impl AsKey for Ipv4Net {
    type KeySize = [u8; 21];
    fn as_key(&self, id: u128, proto: u8) -> Key<Self::KeySize> {
        key(self, id, proto)
    }
}

impl AsKey for Ipv6Net {
    type KeySize = [u8; 33];
    fn as_key(&self, id: u128, proto: u8) -> Key<Self::KeySize> {
        key(self, id, proto)
    }
}

#[cfg(test)]
mod test {

    use aya::maps::lpm_trie::Key;
    use ipnet::{Ipv4Net, Ipv6Net};
    use uuid::Uuid;

    use crate::{cidr::AsKey, Protocol};

    #[test]
    fn as_key_works() {
        let cidr: Ipv4Net = "142.251.134.77/32".parse().unwrap();

        let x = cidr.as_key(0, Protocol::TCP as u8);
        let y = Key::new(
            168,
            [
                0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 142, 251, 134, 77,
            ],
        );
        assert_eq!(x.data, y.data);

        let actual_len = x.prefix_len;
        let expected_len = y.prefix_len;
        assert_eq!(actual_len, expected_len);
    }

    #[test]
    fn as_key_works_24() {
        let cidr: Ipv4Net = "142.251.134.77/24".parse().unwrap();

        let x = cidr.as_key(0, Protocol::TCP as u8);
        let y = Key::new(
            160,
            [
                0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 142, 251, 134, 0,
            ],
        );
        assert_eq!(x.data, y.data);

        let actual_len = x.prefix_len;
        let expected_len = y.prefix_len;
        assert_eq!(actual_len, expected_len);
    }

    #[test]
    fn as_key_works_ipv6() {
        let cidr: Ipv6Net = "fafa::3/128".parse().unwrap();

        let x = cidr.as_key(0, Protocol::TCP as u8);
        let y = Key::new(
            264,
            [
                0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0xfa, 0xfa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            ],
        );
        assert_eq!(x.data, y.data);

        let actual_len = x.prefix_len;
        let expected_len = y.prefix_len;
        assert_eq!(actual_len, expected_len);
    }

    #[test]
    fn as_key_works_with_id() {
        let cidr: Ipv4Net = "1.1.1.1/32".parse().unwrap();
        let id = Uuid::parse_str("95112de5-62df-4fbc-9688-47681b1fe89d").unwrap();

        let x = cidr.as_key(id.as_u128(), Protocol::Generic as u8);
        let y = Key::new(
            168,
            [
                0x9d, 0xe8, 0x1f, 0x1b, 0x68, 0x47, 0x88, 0x96, 0xbc, 0x4f, 0xdf, 0x62, 0xe5, 0x2d,
                0x11, 0x95, 255, 1, 1, 1, 1,
            ],
        );
        assert_eq!(x.data, y.data);

        let actual_len = x.prefix_len;
        let expected_len = y.prefix_len;
        assert_eq!(actual_len, expected_len);
    }
}
