use std::net::Ipv4Addr;

use clap::Parser;
use firewall::{Action, Firewall, Rule};
use ipnet::IpNet;
use tokio::signal;

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

    let mut firewall = Firewall::new(opt.iface)?;
    firewall.set_default_action(Action::Reject)?;

    firewall.add_id("10.13.13.2/32".parse().unwrap(), 1)?;
    firewall.add_id("10.13.13.3/32".parse().unwrap(), 2)?;

    for i in 4..=100 {
        let ip: Ipv4Addr = "10.13.13.0".parse().unwrap();
        let ip = u32::from(ip) + i;
        let ip = Ipv4Addr::from(ip);

        firewall.add_id(IpNet::new(ip.into(), 32).unwrap(), i)?;
    }

    for i in (1..10).step_by(2) {
        firewall.add_rule(
            &Rule::new("10.13.13.3/32".parse().unwrap())
                .with_id(1)
                .with_range(i..=i, firewall::Protocol::Generic),
        )?;
    }
    for i in (60001..60031).step_by(2) {
        firewall.add_rule(
            &Rule::new("10.13.13.3/32".parse().unwrap())
                .with_id(1)
                .with_range(i..=i, firewall::Protocol::Generic),
        )?;
    }
    firewall.add_rule(
        &Rule::new("10.13.13.3/32".parse().unwrap())
            .with_id(1)
            .with_range(1000..=60000, firewall::Protocol::Generic),
    )?;

    for i in (1..40).step_by(2) {
        firewall.add_rule(
            &Rule::new("10.13.13.2/32".parse().unwrap())
                .with_range(i..=i, firewall::Protocol::Generic)
                .with_id(2),
        )?;
    }

    for i in (60001..60011).step_by(2) {
        firewall.add_rule(
            &Rule::new("10.13.13.2/32".parse().unwrap())
                .with_range(i..=i, firewall::Protocol::Generic)
                .with_id(2),
        )?;
    }

    firewall.add_rule(
        &Rule::new("10.13.13.2/32".parse().unwrap())
            .with_range(1000..=60000, firewall::Protocol::Generic)
            .with_id(2),
    )?;

    for i in ((1 << 12) - 10)..(1 << 12) {
        let ip = Ipv4Addr::from((10 << 24) + (13 << 16) + (13 << 8) + i);
        let ip = IpNet::new(ip.into(), 32).unwrap();
        firewall.add_rule(&Rule::new(ip))?;
    }

    firewall.start_logging()?;

    tracing::info!("Firewall started");
    signal::ctrl_c().await?;
    tracing::info!("Exiting...");

    Ok(())
}
