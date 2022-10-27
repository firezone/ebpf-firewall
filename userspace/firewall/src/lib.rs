mod as_octet;
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
