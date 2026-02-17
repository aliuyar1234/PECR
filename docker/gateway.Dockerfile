FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build -p pecr-gateway --release

FROM debian:12-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --system pecr \
    && useradd --system --gid pecr --uid 10001 pecr \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder --chown=pecr:pecr /app/target/release/pecr-gateway /usr/local/bin/pecr-gateway
USER pecr:pecr
EXPOSE 8080
ENTRYPOINT ["pecr-gateway"]
