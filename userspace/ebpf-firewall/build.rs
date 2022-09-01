use std::{path::PathBuf, process::ExitStatus};

fn main() {
    build_ebpf().expect("Couldn't build ebpf artifact");
}

pub fn build_ebpf() -> std::io::Result<ExitStatus> {
    let dir = PathBuf::from("../../ebpf-firewall-ebpf");
    let target = format!("--target={}", "bpfel-unknown-none");
    // Should we: RUSTFLAGS="-C link-arg=--unroll-loops"?
    // 5.3
    let args = vec![
        "+nightly",
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    std::process::Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()
}
