use std::{path::PathBuf, process::ExitStatus};

fn main() {
    println!("cargo:rerun-if-changed=../../ebpf/");
    println!("cargo:rerun-if-changed=../firewall-common/src/");
    let wireguard_enabled = std::env::var("CARGO_FEATURE_WIREGUARD").is_ok();
    let endianess = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let profile = std::env::var("PROFILE").unwrap();
    let out_dir = PathBuf::from("../userspace/target/artifacts");
    let exit_status = build_ebpf(wireguard_enabled, out_dir, endianess, profile)
        .expect("Couldn't build ebpf artifact");
    if !exit_status.success() {
        panic!("couldn't build ebpf, error: {exit_status}")
    }
}

fn get_architecture(endianess: String) -> &'static str {
    match &endianess[..] {
        "big" => "bpfeb-unknown-none",
        "little" => "bpfel-unknown-none",
        _ => panic!("architecture endianess not implemented"),
    }
}

pub fn build_ebpf(
    wireguard_enabled: bool,
    out_dir: PathBuf,
    endianess: String,
    profile: String,
) -> std::io::Result<ExitStatus> {
    let dir = PathBuf::from("../../ebpf");
    let target = format!("--target={}", get_architecture(endianess));
    // Should we: RUSTFLAGS="-C link-arg=--unroll-loops"?
    // 5.3
    let mut args = vec![
        "+nightly",
        "build",
        "--color",
        "always",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];

    if wireguard_enabled {
        args.push("--features");
        args.push("wireguard");
    }

    if profile == "release" {
        args.push("--release");
    }

    std::process::Command::new("cargo")
        .env("CARGO_TARGET_DIR", out_dir)
        .current_dir(&dir)
        .args(&args)
        .status()
}
