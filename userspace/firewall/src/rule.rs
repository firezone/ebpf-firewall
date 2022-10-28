use firewall_common::GENERIC_PROTO;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::ops::RangeInclusive;

// TODO: Use a builder pattern to hide variant visisibility.
/// Rule for the [Firewall](crate::Firewall).
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
    ///
    /// # Example
    /// ```
    /// # use firewall::Rule;
    /// // Rule that matches 10.5.6.0/23
    /// Rule::new("10.5.6.0/23".parse().unwrap());
    /// ```
    pub fn new(dest: IpNet) -> Self {
        match dest {
            IpNet::V4(dest) => Rule::V4(RuleImpl::new(dest)),
            IpNet::V6(dest) => Rule::V6(RuleImpl::new(dest)),
        }
    }

    /// Gives the source ID for the `Rule`.
    ///
    /// For a rule with an ID to match any packet, first you need to associate an IP or multiple IPs with that id.
    /// Then, the rule will match only packets with a source IP that has been associated with that ID.
    ///
    /// Note that this can be updated on the fly, adding or removing ids to a firewall will affect existing Rules.
    ///
    /// To associate an ID with an IP take a look at [add_id](crate::Firewall::add_id).
    ///
    /// IDs can't be 0 since that's used internally as the rule with no-id.
    ///
    /// # Example
    /// ```
    /// # use firewall::Rule;
    /// // Rule that matches a source id
    /// Rule::new("10.5.6.1/32".parse().unwrap()).with_id(10);
    /// ```
    pub fn with_id(self, id: u32) -> Self {
        match self {
            Rule::V4(r) => Rule::V4(r.with_id(id)),
            Rule::V6(r) => Rule::V6(r.with_id(id)),
        }
    }

    /// Sets a port range for the `Rule`.
    ///
    /// The range need to be valid to be accepted when adding the rule to the [Firewall](crate::Firewall).
    ///
    /// A rule with [Protocol::Generic] will match both UDP and TCP.
    ///
    /// # Example
    /// ```
    /// # use firewall::Rule;
    /// // Rule that matches a source id
    /// # use firewall::{Protocol, Firewall};
    /// Rule::new("10.5.6.1/32".parse().unwrap()).with_range(100..=433, Protocol::UDP);
    /// ```
    ///  
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

/// Struct with Protocol types to specify what a given port range affects when creating a [Rule] with [with_range](Rule::with_range).
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
