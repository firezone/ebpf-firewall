//! A userspace library to easily administer an eBPF firewall.
//!
//! The main struct in this library is [Firewall], from there you can create a new instance, add and remove [Rule]s, add and remove IDs (more on the documentation for the firewall)
//!
//! This library loads an eBPF program when creating a [Firewall], the eBPF binary is built along with the library.
//!
//! # Example
//! ```no_run
//! use firewall::{Firewall, Action, Protocol, Rule};
//!
//! // Create a new firewall attached to interface 0
//! let mut fw = Firewall::new("eth0").unwrap();
//!
//! // Sets what happens to a packet that doesn't match any rule.
//! // By default it will be rejected but no harm in being explicit.
//! fw.set_default_action(Action::Reject).unwrap();
//!
//! // Create and add a rule that will accept any packet outgoing to 10.0.0.5.
//! // Note that the only reason this rule works as expected is that rules invert the default behavior.
//! let rule = Rule::new("10.0.0.5/32".parse().unwrap());
//! fw.add_rule(&rule).unwrap();
//!
//! // Add a rule that blocks all out going ssh connections
//! let rule = Rule::new("0.0.0.0/0".parse().unwrap()).with_range(22..=22, Protocol::Generic);
//! fw.add_rule(&rule).unwrap();
//!
//! // Add a rule that blocks all packets going from 10.0.0.3 or 10.0.0.6 to 10.0.0.9
//! let rule = Rule::new("10.0.0.6/32".parse().unwrap()).with_id(1);
//! fw.add_id("10.0.0.3/32".parse().unwrap(), 1).unwrap();
//! fw.add_id("10.0.0.6/32".parse().unwrap(), 1).unwrap();
//! fw.add_rule(&rule).unwrap();
//!
//! // Finally start logging all incoming packets
//! fw.start_logging().unwrap();
//! ```
mod as_octet;
mod bpf_store;
mod cidr;
mod classifier;
mod config;
mod error;
mod firewall;
mod logger;
mod rule;
mod rule_tracker;

pub use crate::firewall::Firewall;
pub use firewall_common::Action;

pub use error::Error;
pub use rule::{Protocol, Rule};
pub type Result<T> = std::result::Result<T, Error>;

const EVENT_ARRAY: &str = "EVENTS";
const SOURCE_ID_IPV4: &str = "SOURCE_ID_IPV4";
const RULE_MAP_IPV4: &str = "RULE_MAP_IPV4";
const SOURCE_ID_IPV6: &str = "SOURCE_ID_IPV6";
const RULE_MAP_IPV6: &str = "RULE_MAP_IPV6";
const CONFIG: &str = "CONFIG";
