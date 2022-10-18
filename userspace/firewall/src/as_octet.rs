use ipnet::{Ipv4Net, Ipv6Net};

pub trait AsOctets {
    type Octets;
    fn as_octets(&self) -> Self::Octets;
}

impl AsOctets for Ipv4Net {
    type Octets = [u8; 4];

    fn as_octets(&self) -> Self::Octets {
        self.addr().octets()
    }
}

impl AsOctets for Ipv6Net {
    type Octets = [u8; 16];

    fn as_octets(&self) -> Self::Octets {
        self.addr().octets()
    }
}
