mod as_octet;
mod cidr;
mod classifier;
mod config;
mod error;
mod logger;
mod rule_tracker;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use as_octet::AsOctets;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};

use cidr::{AsNum, Cidr};
pub use cidr::{Ipv4CIDR, Ipv6CIDR};
pub use classifier::Classifier;
use classifier::{ClassifierV4, ClassifierV6};
pub use config::ConfigHandler;
pub use firewall_common::Action;
use firewall_common::GENERIC_PROTO;
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
    bpf: Bpf,
    rule_tracker_v4: RuleTrackerV4,
    rule_tracker_v6: RuleTrackerV6,
    classifier_v4: ClassifierV4,
    classifier_v6: ClassifierV6,
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

        let rule_tracker_v4 = RuleTrackerV4::new_ipv4(&bpf)?;
        let rule_tracker_v6 = RuleTrackerV6::new_ipv6(&bpf)?;
        let classifier_v4 = ClassifierV4::new_ipv4(&bpf)?;
        let classifier_v6 = ClassifierV6::new_ipv6(&bpf)?;
        let logger = Logger::new(&bpf);

        Ok(Self {
            bpf,
            rule_tracker_v4,
            rule_tracker_v6,
            classifier_v4,
            classifier_v6,
        })
    }

    pub fn add_rule_v4(&mut self, rule: &Rule<Ipv4Addr>) -> Result<()> {
        self.rule_tracker_v4.add_rule(rule)
    }

    pub fn add_rule_v6(&mut self, rule: &Rule<Ipv6Addr>) -> Result<()> {
        self.rule_tracker_v6.add_rule(rule)
    }
    pub fn add_id_v4(&mut self, ip: Ipv4Addr, id: u32) -> Result<()> {
        self.classifier_v4.insert(ip, id)
    }

    pub fn add_id_v6(&mut self, ip: Ipv6Addr, id: u32) -> Result<()> {
        self.classifier_v6.insert(ip, id)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Rule<T: AsNum + From<T::Num> + AsOctets>
where
    T::Octets: AsRef<[u8]>,
{
    id: Option<u32>,
    dest: Cidr<T>,
    port_range: Option<PortRange>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PortRange {
    ports: RangeInclusive<u16>,
    proto: Protocol,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP = 0x06u8,
    UDP = 0x11u8,
    Generic = GENERIC_PROTO,
}
