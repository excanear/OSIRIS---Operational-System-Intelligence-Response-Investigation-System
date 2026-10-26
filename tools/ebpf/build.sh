#!/usr/bin/env bash
# Build the OSIRIS BPF objects (Linux only; cargo never runs this).
#
#   tools/ebpf/build.sh <out_dir>
#
# Writes, for each object (process.bpf.o, net.bpf.o, fs.bpf.o), <out_dir>/<object>
# and <out_dir>/<object>.sha256 (the sidecar the agent's loader verifies).
# Needs clang and libbpf-dev (/usr/include/bpf/bpf_helpers.h). Works from
# any working directory.
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "usage: $0 <out_dir>" >&2
    exit 2
fi
out_dir=$1

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bpf_dir="$repo_root/bpf"

if ! command -v clang >/dev/null 2>&1; then
    echo "error: clang not found; install clang (e.g. apt-get install clang)" >&2
    exit 1
fi
if [ ! -f /usr/include/bpf/bpf_helpers.h ]; then
    echo "error: /usr/include/bpf/bpf_helpers.h not found; install libbpf-dev" >&2
    exit 1
fi

mkdir -p "$out_dir"

for prog in process net fs; do
    clang -target bpf -D__TARGET_ARCH_x86 -g -O2 \
        -I "$bpf_dir" \
        -c "$bpf_dir/$prog.bpf.c" \
        -o "$out_dir/$prog.bpf.o"

    (cd "$out_dir" && sha256sum "$prog.bpf.o" > "$prog.bpf.o.sha256")

    echo "built $out_dir/$prog.bpf.o"
    cat "$out_dir/$prog.bpf.o.sha256"
done
