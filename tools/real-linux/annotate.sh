#!/usr/bin/env bash
# Surfaces real-Linux results as GitHub check-run annotations, which are
# public (job logs and artifacts need GitHub auth). Diagnostic only: it
# always exits 0 and prints nothing when it has nothing to say.
#
#   annotate.sh tail     <error|warning> <title> <file> [lines]
#       the file's last lines (default 30) as one annotation
#   annotate.sh failures <title> <test-output>
#       ::error:: with the failing test names and their panic/assert lines
#       (or the output's tail when none match, e.g. a compile error)
#   annotate.sh ebpf     <test-output> [kept-stack-dirs]
#       ::warning:: with the eBPF backend status lines the scenarios echo and
#       the agent log lines naming the eBPF load or its fallback reason
set -uo pipefail

max_lines=20
# One annotation body; far below GitHub's 64 KB annotation limit.
max_bytes=8000

# emit <level> <title>: stdin becomes one workflow-command annotation, with
# ANSI colours stripped, long lines cut, and %, CR, LF escaped.
emit() {
    local body
    body=$(sed 's/\x1b\[[0-9;]*m//g' | cut -c1-400 | head -c "$max_bytes" |
        awk '{ gsub(/%/, "%25"); gsub(/\r/, "%0D"); printf "%s%%0A", $0 }')
    [ -n "$body" ] || return 0
    # Title is a property: escape the property separators too.
    local title=${2//%/%25}
    title=${title//,/%2C}
    title=${title//:/%3A}
    printf '::%s title=%s::%s\n' "$1" "$title" "$body"
}

mode=${1:-}
case "$mode" in
tail)
    [ -f "${4:-}" ] || exit 0
    tail -n "${5:-30}" "$4" | emit "$2" "$3"
    ;;
failures)
    out=${3:-}
    [ -f "$out" ] || exit 0
    lines=$(
        {
            grep -E '^test .* FAILED$' "$out"
            grep -E -A3 "panicked at" "$out" | grep -v '^--$'
        } | head -n "$max_lines"
    )
    if [ -z "$lines" ]; then
        lines=$(tail -n "$max_lines" "$out")
    fi
    printf '%s\n' "$lines" | emit error "$2"
    ;;
ebpf)
    out=${2:-}
    kept=${3:-}
    {
        [ -f "$out" ] && grep -h 'osiris-ebpf:' "$out"
        if [ -n "$kept" ] && [ -d "$kept" ]; then
            find "$kept" -name agent.log -exec grep -hiE 'ebpf|bpf object|audit fallback' {} +
        fi
    } | head -n "$max_lines" | emit warning "eBPF process backend"
    ;;
*)
    echo "usage: $0 tail|failures|ebpf ..." >&2
    ;;
esac
exit 0
