mod as_octet;
mod cidr;
mod classifier;
mod config;
mod error;
mod logger;
mod rule_tracker;

use std::ops::RangeInclusive;

use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};

pub use classifier::Classifier;
use classifier::{ClassifierV4, ClassifierV6};
pub use config::ConfigHandler;
pub use firewall_common::Action;
use firewall_common::GENERIC_PROTO;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
pub use logger::Logger;
pub use rule_tracker::RuleTracker;

pub use error::Error;
use rule_tracker::{RuleTrackerV4, RuleTrackerV6};
pub type Result<T> = std::result::Result<T, Error>;

const EVENT_ARRAY: &str = "EVENTS";
const SOURCE_ID_IPV4: &str = "SOURCE_ID_IPV4";
const RULE_MAP_IPV4: &str = "RULE_MAP_IPV4";
const SOURCE_ID_IPV6: &str = "SOURCE_ID_IPV6";
const RULE_MAP_IPV6: &str = "RULE_MAP_IPV6";
const CONFIG: &str = "CONFIG";

pub struct Firewall {
    _bpf: Bpf,
    rule_tracker_v4: RuleTrackerV4,
    rule_tracker_v6: RuleTrackerV6,
    classifier_v4: ClassifierV4,
    classifier_v6: ClassifierV6,
    logger: Logger,
    config: ConfigHandler,
}

impl Firewall {
    pub fn new(iface: String) -> Result<Firewall> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/artifacts/bpfel-unknown-none/debug/firewall-ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/artifacts/bpfel-unknown-none/release/firewall-ebpf"
        ))?;

        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        let _ = tc::qdisc_add_clsact(&iface);
        let program: &mut SchedClassifier = bpf.program_mut("ebpf_firewall").unwrap().try_into()?;
        program.load()?;
        program.attach(&iface, TcAttachType::Ingress, 0)?;

        let rule_tracker_v4 = RuleTrackerV4::new(&bpf)?;
        let rule_tracker_v6 = RuleTrackerV6::new(&bpf)?;
        let classifier_v4 = ClassifierV4::new(&bpf)?;
        let classifier_v6 = ClassifierV6::new(&bpf)?;
        let logger = Logger::new(&bpf)?;
        let config = ConfigHandler::new(&bpf)?;

        Ok(Self {
            _bpf: bpf,
            rule_tracker_v4,
            rule_tracker_v6,
            classifier_v4,
            classifier_v6,
            logger,
            config,
        })
    }

    pub fn set_default_action(&mut self, action: Action) -> Result<()> {
        self.config.set_default_action(action)
    }

    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.add_rule(r),
            Rule::V6(r) => self.rule_tracker_v6.add_rule(r),
        }
    }

    pub fn remove_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.remove_rule(r),
            Rule::V6(r) => self.rule_tracker_v6.remove_rule(r),
        }
    }

    pub fn add_id(&mut self, ip: IpNet, id: u32) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.insert(ip, id),
            IpNet::V6(ip) => self.classifier_v6.insert(ip, id),
        }
    }

    pub fn remove_id(&mut self, ip: &IpNet) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.remove(ip),
            IpNet::V6(ip) => self.classifier_v6.remove(ip),
        }
    }

    pub fn start_logging(&mut self) -> Result<()> {
        self.logger.init()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Rule {
    V4(RuleImpl<Ipv4Net>),
    V6(RuleImpl<Ipv6Net>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleImpl<T> {
    id: Option<u32>,
    dest: T,
    port_range: Option<PortRange>,
}

impl<T> RuleImpl<T> {
    fn new(dest: T) -> Self {
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

    fn with_range(self, range: RangeInclusive<u16>, proto: Protocol) -> Self {
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
    pub fn new(dest: IpNet) -> Self {
        match dest {
            IpNet::V4(dest) => Rule::V4(RuleImpl::new(dest)),
            IpNet::V6(dest) => Rule::V6(RuleImpl::new(dest)),
        }
    }

    // TODO: Could avoid repetititon using a lambda for these 2 functions below
    pub fn with_id(self, id: u32) -> Self {
        match self {
            Rule::V4(r) => Rule::V4(r.with_id(id)),
            Rule::V6(r) => Rule::V6(r.with_id(id)),
        }
    }

    pub fn with_range(self, range: RangeInclusive<u16>, proto: Protocol) -> Self {
        match self {
            Rule::V4(r) => Rule::V4(r.with_range(range, proto)),
            Rule::V6(r) => Rule::V6(r.with_range(range, proto)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PortRange {
    ports: RangeInclusive<u16>,
    proto: Protocol,
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
    fn valid_range(&self) -> bool {
        self.ports.len() <= 1 || !self.ports.contains(&0)
    }

    fn unfold(&self) -> Vec<Self> {
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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP = 0x06u8,
    UDP = 0x11u8,
    Generic = GENERIC_PROTO,
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
