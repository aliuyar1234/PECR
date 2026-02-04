#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p pecr-controller --features rlm
cargo run -p pecr-boundary-check
cargo test --workspace
