#!/usr/bin/env bash
# Enforces ARCHITECTURE.md §27's privilege-boundary dependency rules:
# osiris-sensors/*, osiris-ebpf, osiris-kernel must never reach osiris-server
# or osiris-api; osiris-storage-*, osiris-detect, osiris-correlate,
# osiris-risk must never reach osiris-agent; osiris-schema and osiris-fileutil
# must not depend on any other OSIRIS-internal crate (osiris-fileutil sits
# below both the privileged Agent side and the unprivileged Server side, so
# it must stay a leaf). Crates that don't exist yet in the
# workspace are skipped so this script keeps working unmodified as later
# phases add them.
set -euo pipefail

fail=0

crate_exists() {
  cargo tree -p "$1" >/dev/null 2>&1
}

check_no_internal_deps() {
  local crate="$1"
  if ! crate_exists "$crate"; then
    echo "skip: $crate not in workspace yet"
    return
  fi
  local deps
  deps=$(cargo tree -p "$crate" --prefix none | tail -n +2 | grep -E "^osiris-" || true)
  if [ -n "$deps" ]; then
    echo "FAIL: $crate must depend on nothing OSIRIS-internal, found:"
    echo "$deps"
    fail=1
  fi
}

check_forbidden() {
  local crate="$1"
  shift
  if ! crate_exists "$crate"; then
    echo "skip: $crate not in workspace yet"
    return
  fi
  local tree
  tree=$(cargo tree -p "$crate" --prefix none)
  for forbidden in "$@"; do
    if echo "$tree" | grep -qE "^${forbidden}[[:space:]-]"; then
      echo "FAIL: $crate depends on forbidden crate matching '$forbidden' (ARCHITECTURE.md §27)"
      fail=1
    fi
  done
}

check_no_internal_deps osiris-schema
check_no_internal_deps osiris-fileutil
check_forbidden osiris-detect osiris-storage osiris-sensors osiris-agent osiris-server osiris-api
check_forbidden osiris-server osiris-sensors osiris-ebpf osiris-kernel
check_forbidden osiris-api osiris-sensors osiris-ebpf osiris-kernel
check_forbidden osiris-agent osiris-storage osiris-detect osiris-correlate osiris-risk
check_forbidden osiris-sensors-fs osiris-server osiris-api
check_forbidden osiris-sensors-process osiris-server osiris-api
check_forbidden osiris-sensors-net osiris-server osiris-api
check_forbidden osiris-sensors-identity osiris-server osiris-api
check_forbidden osiris-sensors-systemd osiris-server osiris-api

if [ "$fail" -ne 0 ]; then
  echo "Dependency-graph check FAILED"
  exit 1
fi
echo "Dependency-graph check PASSED"
