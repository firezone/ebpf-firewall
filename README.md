# ebpf-firewall

> Note: This readme is still a work in progress

There are 2 main directories:
* `ebpf` for ebpf-related crates
* `userspace` for the user space side of things

This library is composed of 3 crates:
* `firewall-ebpf` with the ebpf code
* `firewall-common` code shared between ebpf and user-space
* `firewall` library code

Furthermore, we have an example of how to use the library in `userspace/firewall/examples/logger-firewall.rs`.

The library exposes functions to log and block traffic.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Regenerate code-bindings

From `userspace`:

```sh
cargo xtask codegen
```

## Build Userspace

To compile:

```sh
cd userspace && cargo build
```

## Run example

```bash
cd userspace && cargo run --example logger-firewall -- --iface <interface_name>
```

## Run Docker builder

To build using docker:
* run `./build-docker-builder.sh`
* run `./build-with-docker.sh`

All flags are passed to `build-with-docker.sh` so if you will run in in wireguard add `--features wireguard` when running the script.

## Run docker tests

After building
```sh
cd userspace/docker
docker compose build
docker compose up
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
