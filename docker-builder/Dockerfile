FROM rust:1.63
RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo install bpf-linker && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME
#rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
#cargo install bpf-linker