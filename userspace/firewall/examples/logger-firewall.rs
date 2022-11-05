use clap::Parser;
use firewall::{Action, Firewall, Protocol, Rule};
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

    let mut firewall = Firewall::new(opt.iface)?;

    firewall.add_id("10.13.13.2/32".parse().unwrap(), 1)?;
    firewall.add_id("fafa::2/128".parse().unwrap(), 1)?;

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

    firewall.add_rule(&Rule::new("142.251.134.78/32".parse().unwrap()))?;
    firewall.start_logging()?;

    tracing::info!("Firewall started");
    signal::ctrl_c().await?;
    tracing::info!("Exiting...");

    Ok(())
}
