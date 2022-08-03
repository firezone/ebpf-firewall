# ebpf-firewall

Right now this logs incoming packet's IP and blocks packets in `BlockList` (Currently `1.1.1.1`).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Regenerate code-bindings

cargo xtask codegen

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run -- --interface <iface_name>
```
