// For now we will use this for CI testing that it just doesn't error out
// (See logger-firewall to actually manual test)

use clap::Parser;
use firewall::{Action, Firewall, Protocol, Rule};

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

    firewall.add_id("10.13.13.2".parse().unwrap(), 1)?;

    firewall.add_id("fafa::2".parse().unwrap(), 1)?;

    firewall.set_default_action(Action::Reject)?;

    firewall.add_rule(
        &Rule::new("fafa::3/128".parse().unwrap())
            .with_id(1)
            .with_range(5000..=6000, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.0.0/16".parse().unwrap())
            .with_id(1)
            .with_range(800..=900, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.0/24".parse().unwrap())
            .with_id(1)
            .with_range(5000..=6000, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.0/24".parse().unwrap())
            .with_id(1)
            .with_range(5800..=6000, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.3/32".parse().unwrap())
            .with_id(1)
            .with_range(300..=400, Protocol::UDP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.3/32".parse().unwrap())
            .with_id(1)
            .with_range(350..=400, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.2/31".parse().unwrap())
            .with_id(1)
            .with_range(7000..=8000, Protocol::Generic),
    )?;

    firewall.remove_rule(
        &Rule::new("10.13.13.0/24".parse().unwrap())
            .with_id(1)
            .with_range(5000..=6000, Protocol::TCP),
    )?;

    firewall.add_rule(
        &Rule::new("10.13.13.3/32".parse().unwrap()).with_range(5000..=6000, Protocol::Generic),
    )?;

    firewall.start_logging()?;
    tracing::info!("Program executed");

    Ok(())
}
