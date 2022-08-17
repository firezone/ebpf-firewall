mod rule_tracker;

use aya::maps::lpm_trie::LpmTrie;
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use ebpf_firewall_common::{ActionStore, PacketLog, MAX_RULES};
use log::info;
use rule_tracker::RuleTracker;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::net::Ipv4Addr;
use tokio::signal;

use crate::rule_tracker::CIDR;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
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

    let mut classifier: HashMap<_, [u8; 4], u32> = HashMap::try_from(bpf.map_mut("CLASSIFIER")?)?;
    // O_o what? insert doesn't require mut for some reason in LpmTrie.
    let blocklist: LpmTrie<_, [u8; 8], ActionStore> = LpmTrie::try_from(bpf.map_mut("BLOCKLIST")?)?;
    let mut rule_tracker = RuleTracker::new(blocklist);
    classifier.insert([10, 13, 13, 2], 1, 0)?;
    let mut action_store = ActionStore::new();
    action_store.add(5000, 6000, false).unwrap();

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
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = Ipv4Addr::from(data.source);
                    let dst_addr = Ipv4Addr::from(data.dest);
                    let action = data.action;
                    let port = data.port;
                    println!(
                        "LOG: SRC {src_addr:?}, DST {dst_addr:?}, PORT: {port} ,action {action}"
                    )
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
