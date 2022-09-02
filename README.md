# ebpf-firewall

> Note: This readme is still a work in progress

This library is composed of 3 crates:
* `ebpf-firewall-ebpf` with the ebpf code
* `ebpf-firewall-common` code shared between ebpf and user-space
* `ebpf-firewall` library code

Furthermore, we have an example of how to use the library in `ebpf-firewall/examples/logger-firewall.rs`.

The library exposes functions to log and block traffic.

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
Furthermore, you want to pass `--feature wireguard` if you want to use the generated ebpf code with a wireguard interface.

## Regenerate code-bindings

cargo xtask codegen

## Build Userspace

Before building userspace library be sure to have built ebpf, the crate includes the bytes from the generated binary object when compling.

To compile:

```bash
cargo build
```

> TODO: Add xtask action to build and run example

## Run example

```bash
cargo run --example logger-firewall -- --iface <interface_name>
```
## Minimum Kernel Requirements (TODO)

* Bounded loops require kernel 5.3 [see here](https://lwn.net/Articles/794934/)
> Note: We can pass `RUSTFLAGS=-C link-arg=--unroll-loops` to let the compiler try to unroll them instead.
* LPM Trie requires version 4.11

| Architecture | Common devices | Minimum kernel required |
| --- | --- | --- |
| `amd64` | Commodity hardware | |
| `armv7` | Embedded devices | |
| `arm64` | Commodity hardware, embedded devices | |
| `MIPS` | Embedded devices | |
| `RISC-V` | Embedded devices | |
