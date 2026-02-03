FROM rust:1.91 AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build -p pecr-controller --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pecr-controller /usr/local/bin/pecr-controller
EXPOSE 8081
ENTRYPOINT ["pecr-controller"]

