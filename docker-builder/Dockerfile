FROM rust:1.66-slim
RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo install bpf-linker && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME
