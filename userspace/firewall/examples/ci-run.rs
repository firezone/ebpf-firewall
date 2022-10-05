// For now we will use this for CI testing that it just doesn't error out
// (See logger-firewall to actually manual test)
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use clap::Parser;
use firewall::{init, Action, Classifier, ConfigHandler, Logger, Protocol, RuleTracker};

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

// Some runners need to update its rlimit to create the maps we use without problems
// I plan to do the map size configurable through features but for now this might work
// See: https://github.com/aya-rs/aya-template/pull/51
fn bump_memlock_rlimit() -> Result<(), anyhow::Error> {
    let rlimit = libc::rlimit {
        rlim_cur: 2048 << 20,
        rlim_max: libc::RLIM_INFINITY,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        anyhow::bail!("Failed to increase rlimit");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    tracing_subscriber::fmt::init();

    bump_memlock_rlimit()?;
    let program = init(opt.iface)?;

    let mut classifier = Classifier::new_ipv4(&program)?;
    classifier.insert(Ipv4Addr::new(10, 13, 13, 2), 1)?;

    let mut classifier_v6 = Classifier::new_ipv6(&program)?;
    classifier_v6.insert(Ipv6Addr::from_str("fafa::2").unwrap(), 1)?;

    let mut config_handler = ConfigHandler::new(&program)?;
    config_handler.set_default_action(Action::Reject)?;

    let mut rule_tracker = RuleTracker::new_ipv4(&program)?;
    let mut rule_tracker_v6 = RuleTracker::new_ipv6(&program)?;

    rule_tracker_v6.add_rule(
        1,
        "fafa::3/128".parse().unwrap(),
        5000..=6000,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(1, "10.13.0.0/16".parse().unwrap(), 800..=900, Protocol::TCP)?;

    rule_tracker.add_rule(
        1,
        "10.13.13.0/24".parse().unwrap(),
        5000..=6000,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        "10.13.13.0/24".parse().unwrap(),
        5800..=6000,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        "10.13.13.3/32".parse().unwrap(),
        300..=400,
        Protocol::UDP,
    )?;

    rule_tracker.add_rule(
        1,
        "10.13.13.3/32".parse().unwrap(),
        350..=400,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        1,
        "10.13.13.2/31".parse().unwrap(),
        7000..=8000,
        Protocol::Generic,
    )?;

    rule_tracker.remove_rule(
        1,
        "10.13.13.0/24".parse().unwrap(),
        5000..=6000,
        Protocol::TCP,
    )?;

    rule_tracker.add_rule(
        0,
        "10.13.13.3/32".parse().unwrap(),
        5000..=6000,
        Protocol::Generic,
    )?;

    let mut logger = Logger::new(&program)?;
    logger.init()?;
    tracing::info!("Program executed");

    Ok(())
}
