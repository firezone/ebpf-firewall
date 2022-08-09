use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use ebpf_firewall_common::PacketLog;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::net::{self, Ipv4Addr};
use tokio::signal;

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

    // O_o what? insert doesn't require mut for some reason in LpmTrie.
    let mut classifier: HashMap<_, [u8; 4], u32> = HashMap::try_from(bpf.map_mut("CLASSIFIER")?)?;
    let blocklist: LpmTrie<_, [u8; 8], i32> = LpmTrie::try_from(bpf.map_mut("BLOCKLIST")?)?;
    let block_addr: [u8; 8] = [0, 0, 0, 0, 1, 1, 1, 0];
    classifier.insert([142, 250, 79, 142], 1, 0)?;
    blocklist.insert(&Key::new(56, block_addr), 0, 0)?;
    let block_addr: [u8; 8] = [0, 0, 0, 1, 192, 168, 0, 197];
    blocklist.insert(&Key::new(64, block_addr), 0, 0)?;

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
                    let src_addr = data.source;
                    let dst_addr = data.dest;
                    let action = data.action;
                    println!("LOG: SRC {src_addr:?}, DST {dst_addr:?}, action {action}")
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
