use std::{path::PathBuf, process::ExitStatus};

const EBPF_FEATURES: &[&str] = &["rules", "wireguard"];
const TOOLCHAIN: &str = "+nightly-2023-01-10";

fn main() {
    println!("cargo:rerun-if-changed=../../ebpf/");
    println!("cargo:rerun-if-changed=../firewall-common/src/");
    let endianess = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let profile = std::env::var("PROFILE").unwrap();
    let out_dir = PathBuf::from("../userspace/target/artifacts");
    let exit_status =
        build_ebpf(out_dir, endianess, profile).expect("Couldn't build ebpf artifact");
    if !exit_status.success() {
        panic!("couldn't build ebpf, error: {exit_status}")
    }
}

fn get_ebpf_features() -> Vec<String> {
    std::env::vars()
        .map(|(k, _)| k)
        .filter_map(|feat| feat.strip_prefix("CARGO_FEATURE_").map(ToString::to_string))
        .map(|feat| feat.to_lowercase())
        .filter(|feat| EBPF_FEATURES.contains(&feat.as_str()))
        .collect()
}

fn get_architecture(endianess: String) -> &'static str {
    match &endianess[..] {
        "big" => "bpfeb-unknown-none",
        "little" => "bpfel-unknown-none",
        _ => panic!("architecture endianess not implemented"),
    }
}

pub fn build_ebpf(
    out_dir: PathBuf,
    endianess: String,
    profile: String,
) -> std::io::Result<ExitStatus> {
    let dir = PathBuf::from("../../ebpf");
    let target = format!("--target={}", get_architecture(endianess));
    // Should we: RUSTFLAGS="-C link-arg=--unroll-loops"?
    // 5.3
    let mut args = vec![
        TOOLCHAIN,
        "build",
        "--color",
        "always",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];

    let features = get_ebpf_features();
    for feature in features.iter() {
        args.push("--features");
        args.push(feature);
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
