mod classifier;
mod logger;
mod rule_tracker;

use anyhow::Result;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};

pub use classifier::Classifier;
pub use logger::Logger;
pub use rule_tracker::RuleTracker;
pub use rule_tracker::CIDR;

const EVENT_ARRAY: &'static str = "EVENTS";
const CLASSIFIER_MAP: &'static str = "CLASSIFIER";
const BLOCK_TRIE: &'static str = "BLOCKLIST";

pub fn load_program(iface: String) -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-firewall"
    ))?;

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = bpf.program_mut("ebpf_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Ingress)?;

    Ok(bpf)
}
