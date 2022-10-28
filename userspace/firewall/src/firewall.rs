use aya::{
    include_bytes_aligned,
    programs::{tc, SchedClassifier, TcAttachType},
    Bpf,
};
use firewall_common::Action;
use ipnet::IpNet;

use crate::{
    classifier::{ClassifierV4, ClassifierV6},
    config::ConfigHandler,
    logger::Logger,
    rule_tracker::{RuleTrackerV4, RuleTrackerV6},
    Result, Rule,
};

/// Represents a Firewall currently blocking/allowing packets.
///
/// Packets will be dropped or accepted given the action set by [`set_default_action`](Firewall::set_default_action).
/// Specific rules will invert this behavior for a given IP and optionally port range.
///
/// Firewall can also log incoming packets using [tracing], currently hardcoded at `info` level by using [start_logging](Self::start_logging).
///
/// See example at the [crate-level doc](crate#example).
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
    /// Creates a new [Firewall] for the given interface.
    ///
    /// The interface must already exists when calling this function.
    ///
    /// As soon as the [Firewall] is created it will start filtering packets.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::Firewall;
    /// let fw = Firewall::new("eth0").unwrap();
    /// ```
    pub fn new(iface: impl AsRef<str>) -> Result<Firewall> {
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
        let _ = tc::qdisc_add_clsact(iface.as_ref());
        let program: &mut SchedClassifier = bpf.program_mut("ebpf_firewall").unwrap().try_into()?;
        program.load()?;
        program.attach(iface.as_ref(), TcAttachType::Ingress, 0)?;

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

    /// Picks default action for firewall either [Accept](Action::Accept) or [Reject](Action::Reject).
    ///
    /// * `Accept`: All packets will be accepted by default and will be dropped if they match a rule.
    /// * `Reject`: All packets will be dropped by default and will be accepted if they match a rule.
    ///
    /// If not specified it will be set to `Reject`.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Action};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// fw.set_default_action(Action::Accept).unwrap();
    /// ```
    pub fn set_default_action(&mut self, action: Action) -> Result<()> {
        self.config.set_default_action(action)
    }

    /// Adds a [Rule] for the firewall.
    ///
    /// The behavior of a rule is determined by the [`set_default_action`](Firewall::set_default_action).
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Rule};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// let rule = Rule::new("10.0.0.5/32".parse().unwrap());
    /// fw.add_rule(&rule).unwrap();
    /// ```
    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.add_rule(r),
            Rule::V6(r) => self.rule_tracker_v6.add_rule(r),
        }
    }

    /// Removes an existing [Rule] from the firewall.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Rule};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// let rule = Rule::new("10.0.0.5/32".parse().unwrap());
    /// fw.add_rule(&rule).unwrap();
    /// fw.remove_rule(&rule).unwrap();
    /// ```
    pub fn remove_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.remove_rule(r),
            Rule::V6(r) => self.rule_tracker_v6.remove_rule(r),
        }
    }

    /// Associates an `id` which is any `u32` except for 0 with a given IP.
    ///
    /// Rules with the `id` will match only for source ips associated with that id.
    ///
    /// An id can be associated with multiple ips.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Rule};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// fw.add_id("10.0.0.5/32".parse().unwrap(), 1).unwrap();
    /// fw.add_id("10.0.0.6/32".parse().unwrap(), 1).unwrap();
    /// // Block all traffic from 10.0.0.5 and 10.0.0.6 to any IP in the range 10.0.1.0/24
    /// let rule = Rule::new("10.0.1.0/24".parse().unwrap()).with_id(1);
    /// fw.add_rule(&rule).unwrap();
    /// ```
    pub fn add_id(&mut self, ip: IpNet, id: u32) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.insert(ip, id),
            IpNet::V6(ip) => self.classifier_v6.insert(ip, id),
        }
    }

    /// Removes the association between a given ip and its id.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Rule};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// fw.add_id("10.0.0.5/32".parse().unwrap(), 1).unwrap();
    /// fw.remove_id(&"10.0.0.6/32".parse().unwrap()).unwrap();
    /// ```
    pub fn remove_id(&mut self, ip: &IpNet) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.remove(ip),
            IpNet::V6(ip) => self.classifier_v6.remove(ip),
        }
    }

    /// Given the id removes all associated IPs
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::{Firewall, Rule};
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// fw.add_id("10.0.0.5/32".parse().unwrap(), 1).unwrap();
    /// fw.add_id("10.0.0.6/32".parse().unwrap(), 1).unwrap();
    /// // Removes both 10.0.0.5 and 10.0.0.6
    /// fw.remove_by_id(1).unwrap();
    /// ```
    pub fn remove_by_id(&mut self, id: u32) -> Result<()> {
        self.classifier_v4.remove_by_id(id)?;
        self.classifier_v6.remove_by_id(id)?;
        Ok(())
    }

    /// Starts logging incoming packets to `info` level fo the [tracing] crate.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::Firewall;
    /// let mut fw = Firewall::new("eth0").unwrap();
    /// fw.start_logging().unwrap();
    /// ```
    pub fn start_logging(&mut self) -> Result<()> {
        self.logger.init()
    }
}
