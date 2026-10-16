#!/usr/bin/env bash
# Builds stamp-recv (and clock-echo) outside the workspace, so a receiver host
# does not have to fetch the whole workspace's dependencies (Solana, Jito git
# repositories) just for this small tool. Needs only a Rust toolchain.
#
# Usage: fanout-bench/scripts/build-receiver.sh
# Result: target/receiver/release/stamp-recv
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$ROOT/target/receiver-src"
rm -rf "$WORK"
mkdir -p "$WORK"
cp -r "$ROOT/fanout-bench/src" "$WORK/src"

cat >"$WORK/Cargo.toml" <<'EOF'
[package]
name = "fanout-bench"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
clap = { version = "4", features = ["derive", "env"] }
libc = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[[bin]]
name = "stamp-recv"
path = "src/bin/stamp_recv.rs"

[[bin]]
name = "clock-echo"
path = "src/bin/clock_echo.rs"

[profile.release]
opt-level = 3
EOF

# Same dependency versions as the workspace build (cargo drops the rest), so
# older toolchains work too.
cp "$ROOT/Cargo.lock" "$WORK/Cargo.lock"
# The other binaries are not needed here.
find "$WORK/src/bin" -name '*.rs' ! -name stamp_recv.rs ! -name clock_echo.rs -delete
cargo build --release --manifest-path "$WORK/Cargo.toml" --target-dir "$ROOT/target/receiver"
echo "built $ROOT/target/receiver/release/stamp-recv"
