use std::net::Ipv4Addr;

use clap::Parser;
use ebpf_firewall::{init, Classifier, Logger, Protocol, RuleTracker, CIDR};
use tokio::signal;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    tracing_subscriber::fmt::init();

    let bpf = init(opt.iface)?;

    let mut classifier = Classifier::new(&bpf)?;
    classifier.insert(Ipv4Addr::new(10, 13, 13, 2), 1)?;

    let mut rule_tracker = RuleTracker::new(&bpf)?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 0, 0), 16),
        800..=900,
        false,
        0,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 0), 24),
        5000..=6000,
        false,
        0,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 0), 24),
        5800..=6000,
        false,
        0,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 3), 32),
        300..=400,
        false,
        100,
        Protocol::UDP,
    )?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 3), 32),
        350..=400,
        false,
        0,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 2), 31),
        7000..=8000,
        false,
        0,
        Protocol::Generic,
    )?;

    rule_tracker.remove_rule(
        1,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 0), 24),
        5000..=6000,
        false,
        0,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        0,
        CIDR::new(Ipv4Addr::new(10, 13, 13, 3), 32),
        5000..=6000,
        false,
        0,
        Protocol::Generic,
    )?;

    let mut logger = Logger::new(&bpf)?;
    logger.init()?;
    signal::ctrl_c().await?;
    tracing::info!("Exiting...");

    Ok(())
}
