#!/usr/bin/env bash
# Runs the benchmark matrix on a prepared host and keeps the JSON lines.
# Usage: bench.sh [--skip-agent | --agent-only] [out-file]
#   default      pipeline + query + ingest + agent (agent needs real auditd)
#   --skip-agent everything except the agent bench (WSL has no auditd)
#   --agent-only only the agent bench (GitHub Actions workflow)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "bench.sh must run as root"; exit 1; }
mode=all
case "${1:-}" in
  --skip-agent) mode=skip-agent; shift ;;
  --agent-only) mode=agent-only; shift ;;
esac
out="${1:-/tmp/osiris-bench.jsonl}"
source "$HOME/.cargo/env" 2>/dev/null || true
root="$(cd "$(dirname "$0")/../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/osiris-target}"
export OSIRIS_BIN_DIR="$CARGO_TARGET_DIR/release"
cd "$root"
cargo build --release -p osiris-server -p osiris-agent -p osiris-bench
bench="$OSIRIS_BIN_DIR/osiris-bench"
: > "$out"
case "$mode" in
  all)        "$bench" all | tee -a "$out" ;;
  skip-agent) "$bench" all --skip-agent | tee -a "$out" ;;
  agent-only) "$bench" all --agent-only | tee -a "$out" ;;
esac
