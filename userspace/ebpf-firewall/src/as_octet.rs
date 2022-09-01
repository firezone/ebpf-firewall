pub trait AsOctets {
    type Octets;
    fn as_octets(&self) -> Self::Octets;
}

impl AsOctets for std::net::Ipv4Addr {
    type Octets = [u8; 4];

    fn as_octets(&self) -> Self::Octets {
        self.octets()
    }
}

impl AsOctets for std::net::Ipv6Addr {
    type Octets = [u8; 16];

    fn as_octets(&self) -> Self::Octets {
        self.octets()
    }
}
