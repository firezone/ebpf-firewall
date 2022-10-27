use firewall_common::GENERIC_PROTO;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::ops::RangeInclusive;

// TODO: Use a builder pattern to hide variant visisibility.
/// Rule for the [Firewall].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Rule {
    V4(RuleImpl<Ipv4Net>),
    V6(RuleImpl<Ipv6Net>),
}

#[doc(hidden)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleImpl<T> {
    pub(crate) id: Option<u32>,
    pub(crate) dest: T,
    pub(crate) port_range: Option<PortRange>,
}

impl<T> RuleImpl<T> {
    pub(crate) fn new(dest: T) -> Self {
        Self {
            dest,
            id: None,
            port_range: None,
        }
    }

    fn with_id(self, id: u32) -> Self {
        Self {
            id: Some(id),
            ..self
        }
    }

    pub(crate) fn with_range(self, range: RangeInclusive<u16>, proto: Protocol) -> Self {
        Self {
            port_range: Some(PortRange {
                ports: range,
                proto,
            }),
            ..self
        }
    }
}

impl Rule {
    /// Creates a new `Rule` with a given destination.
    pub fn new(dest: IpNet) -> Self {
        match dest {
            IpNet::V4(dest) => Rule::V4(RuleImpl::new(dest)),
            IpNet::V6(dest) => Rule::V6(RuleImpl::new(dest)),
        }
    }

    /// Gives the source id for the `Rule`.
    pub fn with_id(self, id: u32) -> Self {
        match self {
            Rule::V4(r) => Rule::V4(r.with_id(id)),
            Rule::V6(r) => Rule::V6(r.with_id(id)),
        }
    }

    /// Sets a port range for the `Rule`.
    pub fn with_range(self, range: RangeInclusive<u16>, proto: Protocol) -> Self {
        match self {
            Rule::V4(r) => Rule::V4(r.with_range(range, proto)),
            Rule::V6(r) => Rule::V6(r.with_range(range, proto)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub(crate) struct PortRange {
    pub(crate) ports: RangeInclusive<u16>,
    pub(crate) proto: Protocol,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            ports: 0..=0,
            proto: Protocol::Generic,
        }
    }
}

impl PortRange {
    pub(crate) fn valid_range(&self) -> bool {
        self.ports.len() <= 1 || !self.ports.contains(&0)
    }

    pub(crate) fn unfold(&self) -> Vec<Self> {
        self.proto
            .unfold()
            .iter()
            .map(|&proto| PortRange {
                ports: self.ports.clone(),
                proto,
            })
            .collect()
    }
}

/// Struct with Protocol numbers for [Rule]s port-ranges.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP Protocol port range.
    TCP = 0x06u8,
    /// UDP Protocol port range.
    UDP = 0x11u8,
    /// Generic protocol, represents a port range that involves both UDP and TCP.
    Generic = GENERIC_PROTO,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Generic
    }
}

impl Protocol {
    fn unfold(&self) -> Vec<Self> {
        if *self == Protocol::Generic {
            vec![Self::TCP, Self::UDP]
        } else {
            vec![self.clone()]
        }
    }
}
