use std::convert::TryFrom;

use aya::{
    include_bytes_aligned,
    maps::{HashMap, LpmTrie},
    programs::{tc, SchedClassifier, TcAttachType},
    Bpf,
};
use firewall_common::Action;
use ipnet::IpNet;
use tracing::instrument;

use crate::{
    classifier::{ClassifierV4, ClassifierV6},
    config::ConfigHandler,
    logger::Logger,
    rule_tracker::{RuleTrackerV4, RuleTrackerV6},
    Error::MapNotFound,
    Result, Rule, RULE_MAP_IPV4, RULE_MAP_IPV6, SOURCE_ID_IPV4, SOURCE_ID_IPV6,
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
    bpf: Bpf,
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
    /// The interface must already exist when calling this function.
    ///
    /// As soon as the [Firewall] is created it will start filtering packets.
    ///
    /// # Example
    /// ```no_run
    /// # use firewall::Firewall;
    /// let fw = Firewall::new("eth0").unwrap();
    /// ```
    #[instrument(level = "trace")]
    pub fn new(iface: impl AsRef<str> + std::fmt::Debug) -> Result<Firewall> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/artifacts/bpfel-unknown-none/debug/firewall-ebpf"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/artifacts/bpfel-unknown-none/release/firewall-ebpf"
        ))?;
        tracing::trace!("Created bpf program in memory");

        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        tc::qdisc_add_clsact(iface.as_ref())?;
        tracing::trace!("Added qdisc clsact to {}", iface.as_ref());

        let program: &mut SchedClassifier = bpf
            .program_mut("ebpf_firewall")
            .expect("Couldn't retrieve reference to program with given name")
            .try_into()?;
        program.load()?;
        tracing::trace!("Loaded ebpf program");

        program.attach(iface.as_ref(), TcAttachType::Ingress, 0)?;
        tracing::trace!("Attached program to interface");

        let rule_tracker_v4 = RuleTrackerV4::new()?;
        let rule_tracker_v6 = RuleTrackerV6::new()?;
        let classifier_v4 = ClassifierV4::new()?;
        let classifier_v6 = ClassifierV6::new()?;
        let logger = Logger::new()?;
        let config = ConfigHandler::new()?;
        tracing::trace!("Successfully created userspace references to ebpf maps");

        Ok(Self {
            bpf,
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
    #[instrument(level = "trace", skip(self))]
    pub fn set_default_action(&mut self, action: Action) -> Result<()> {
        self.config.set_default_action(&mut self.bpf, action)
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
    #[instrument(level = "trace", skip(self))]
    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.add_rule(
                &mut LpmTrie::try_from(self.bpf.map_mut(RULE_MAP_IPV4).ok_or(MapNotFound)?)?,
                r,
            ),
            Rule::V6(r) => self.rule_tracker_v6.add_rule(
                &mut LpmTrie::try_from(self.bpf.map_mut(RULE_MAP_IPV6).ok_or(MapNotFound)?)?,
                r,
            ),
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
    #[instrument(level = "trace", skip(self))]
    pub fn remove_rule(&mut self, rule: &Rule) -> Result<()> {
        match &rule {
            Rule::V4(r) => self.rule_tracker_v4.remove_rule(
                &mut LpmTrie::try_from(self.bpf.map_mut(RULE_MAP_IPV4).ok_or(MapNotFound)?)?,
                r,
            ),
            Rule::V6(r) => self.rule_tracker_v6.remove_rule(
                &mut LpmTrie::try_from(self.bpf.map_mut(RULE_MAP_IPV6).ok_or(MapNotFound)?)?,
                r,
            ),
        }
    }

    /// Associates an `id` which is any `u128` except for 0 with a given IP.
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
    #[instrument(level = "trace", skip(self))]
    pub fn add_id(&mut self, ip: IpNet, id: u128) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.insert(
                &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV4).ok_or(MapNotFound)?)?,
                ip,
                id,
            ),
            IpNet::V6(ip) => self.classifier_v6.insert(
                &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV6).ok_or(MapNotFound)?)?,
                ip,
                id,
            ),
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
    #[instrument(level = "trace", skip(self))]
    pub fn remove_id(&mut self, ip: &IpNet) -> Result<()> {
        match ip {
            IpNet::V4(ip) => self.classifier_v4.remove(
                &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV4).ok_or(MapNotFound)?)?,
                ip,
            ),
            IpNet::V6(ip) => self.classifier_v6.remove(
                &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV6).ok_or(MapNotFound)?)?,
                ip,
            ),
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
    #[instrument(level = "trace", skip(self))]
    pub fn remove_by_id(&mut self, id: u128) -> Result<()> {
        self.classifier_v4.remove_by_id(
            &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV4).ok_or(MapNotFound)?)?,
            id,
        )?;
        self.classifier_v6.remove_by_id(
            &mut HashMap::try_from(self.bpf.map_mut(SOURCE_ID_IPV6).ok_or(MapNotFound)?)?,
            id,
        )?;
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
    #[instrument(level = "trace", skip(self))]
    pub fn start_logging(&mut self) -> Result<()> {
        self.logger.init(&mut self.bpf)
    }
}
