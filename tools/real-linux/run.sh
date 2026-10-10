#!/usr/bin/env bash
# Builds the release binaries into a Linux-side target dir and runs the
# real-Linux suite serially. Usage: run.sh [test-name-filter]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run.sh must run as root"; exit 1; }
source "$HOME/.cargo/env" 2>/dev/null || true
root="$(cd "$(dirname "$0")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/osiris-target}"
export OSIRIS_BIN_DIR="$CARGO_TARGET_DIR/release"
cd "$root"
cargo build --release -p osiris-server -p osiris-agent
cargo test --release -p osiris-real-linux-tests --test real_linux -- --ignored --test-threads=1 "$@"
