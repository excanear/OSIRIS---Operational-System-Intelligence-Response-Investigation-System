#!/usr/bin/env bash
# Prepares a WSL/VM Linux host for the OSIRIS real-Linux suite. Idempotent.
# With OSIRIS_BPF_DIR set, also builds the BPF object (and its sha256
# sidecar) there for the eBPF process backend; the log is <dir>/build.log.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "setup.sh must run as root (auditd, /etc/osiris)"; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq auditd curl sudo tcpdump build-essential pkg-config libssl-dev \
  clang libbpf-dev >/dev/null
mkdir -p /tmp/osiris-p10 /var/www /etc/osiris
install -m 0640 "$here/osiris.rules" /etc/audit/rules.d/osiris.rules
systemctl enable --now auditd >/dev/null || {
  echo "auditd failed to start. On WSL2 the distro runs in a child PID namespace and the kernel"
  echo "refuses audit control from it (auditctl -s: Operation not permitted); use a real VM/host."
  exit 1
}
augenrules --load >/dev/null
auditctl -l | grep -q osiris_exec || { echo "audit rules did not load"; exit 1; }
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
bpf="no OSIRIS_BPF_DIR"
if [ -n "${OSIRIS_BPF_DIR:-}" ]; then
  mkdir -p "$OSIRIS_BPF_DIR"
  log="$OSIRIS_BPF_DIR/build.log"
  if ! "$here/../ebpf/build.sh" "$OSIRIS_BPF_DIR" >"$log" 2>&1; then
    # On GitHub Actions this becomes a public check-run annotation.
    "$here/annotate.sh" tail error "eBPF object build failed" "$log" 40
    echo "BPF object build failed:"; cat "$log"
    exit 1
  fi
  bpf="bpf object in $OSIRIS_BPF_DIR, clang $(clang -dumpversion)"
fi
echo "ok: auditd $(auditctl -v | awk '{print $NF}'), $(systemctl --version | head -1), kernel $(uname -r), $bpf"
