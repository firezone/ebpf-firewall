mod rule_tracker;

use anyhow::Result;
use aya::maps::perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer};
use aya::maps::Map;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use ebpf_firewall_common::PacketLog;
use rule_tracker::RuleTracker;
use std::net::Ipv4Addr;
use std::ops::DerefMut;
use tokio::signal;
use tracing;

use crate::classifier::Classifier;
use crate::rule_tracker::CIDR;

mod classifier;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

fn load_program(opt: Opt) -> Result<Bpf> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-firewall"
    ))?;

    BpfLogger::init(&mut bpf)?;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.

    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("ebpf_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    Ok(bpf)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    tracing_subscriber::fmt::init();

    let bpf = load_program(opt)?;

    let mut classifier = Classifier::new(&bpf, "CLASSIFIER")?;
    classifier.insert(Ipv4Addr::new(10, 13, 13, 2), 1)?;

    let mut rule_tracker = RuleTracker::new(&bpf, "BLOCKLIST")?;

    rule_tracker
        .add_rule(
            1,
            CIDR::new(Ipv4Addr::new(10, 13, 13, 0), 24),
            5000,
            6000,
            false,
        )
        .unwrap();

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(log_events(buf));
    }

    signal::ctrl_c().await?;
    tracing::info!("Exiting...");

    Ok(())
}

async fn log_events<T: DerefMut<Target = Map>>(mut buf: AsyncPerfEventArrayBuffer<T>) {
    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(1024))
        .collect::<Vec<_>>();
    loop {
        let events = buf.read_events(&mut buffers).await.unwrap();
        for i in 0..events.read {
            let buf = &mut buffers[i];
            let ptr = buf.as_ptr() as *const PacketLog;
            let data = unsafe { ptr.read_unaligned() };
            tracing::info!("BPF processed packet: {data}");
        }
    }
}
