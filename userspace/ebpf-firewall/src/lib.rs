mod as_octet;
mod cidr;
mod classifier;
mod error;
mod logger;
mod rule_tracker;

use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};

pub use cidr::{Ipv4CIDR, Ipv6CIDR};
pub use classifier::Classifier;
pub use ebpf_firewall_common::Action;
use ebpf_firewall_common::GENERIC_PROTO;
pub use logger::Logger;
pub use rule_tracker::RuleTracker;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

const EVENT_ARRAY: &str = "EVENTS";
const SOURCE_ID_IPV4: &str = "SOURCE_ID_IPV4";
const ACTION_MAP_IPV4: &str = "ACTION_MAP_IPV4";
const SOURCE_ID_IPV6: &str = "SOURCE_ID_IPV6";
const ACTION_MAP_IPV6: &str = "ACTION_MAP_IPV6";

pub fn init(iface: String) -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/ebpf-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/ebpf-firewall"
    ))?;

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = bpf.program_mut("ebpf_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress, 0)?;

    Ok(bpf)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP = 0x06u8,
    UDP = 0x11u8,
    Generic = GENERIC_PROTO,
}
