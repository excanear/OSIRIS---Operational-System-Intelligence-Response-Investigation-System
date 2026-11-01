#!/usr/bin/env bash
# Runs a throwaway ClickHouse server on 127.0.0.1:8123 for the
# osiris-storage-clickhouse tests (Phase 11c). Linux / WSL only.
#
#   bash tools/clickhouse/dev-server.sh
#   OSIRIS_CLICKHOUSE_URL=http://127.0.0.1:8123 \
#     cargo test -p osiris-storage-clickhouse -- --include-ignored
#
# The version is pinned to the same exact LTS as the CI service container
# (.github/workflows/ci.yml). The static binary is downloaded once, checked
# against the release's sha512 file and cached under
# ~/.cache/osiris-clickhouse/<version>; every run starts from an empty data
# directory under a temp path, which is deleted when the server exits.
# Safe to re-run. Stop it with Ctrl-C (or kill the process).
#
# Why 26.3 and not the newer 26.8 LTS: the 26.8 amd64 binary dies with
# SIGILL on pre-AVX2 CPUs (it was verified on a Sandy Bridge host), while
# 26.3 runs on any x86-64-v2 CPU. CLICKHOUSE_VERSION overrides the pin for
# experiments only; tests are verified against the pinned version.
set -euo pipefail

VERSION="${CLICKHOUSE_VERSION:-26.3.60.2}"
ARCH="amd64"
case "$(uname -m)" in
  x86_64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ASSET="clickhouse-common-static-${VERSION}-${ARCH}.tgz"
BASE_URL="https://github.com/ClickHouse/ClickHouse/releases/download/v${VERSION}-lts"
CACHE_DIR="${HOME}/.cache/osiris-clickhouse/${VERSION}"
BIN="${CACHE_DIR}/clickhouse"

if [ ! -x "$BIN" ]; then
  mkdir -p "$CACHE_DIR"
  echo "downloading ClickHouse ${VERSION} (${ARCH})..."
  curl -fL --retry 3 -o "${CACHE_DIR}/${ASSET}.part" "${BASE_URL}/${ASSET}"
  curl -fL --retry 3 -o "${CACHE_DIR}/${ASSET}.sha512" "${BASE_URL}/${ASSET}.sha512"
  expected=$(awk '{print $1}' "${CACHE_DIR}/${ASSET}.sha512")
  actual=$(sha512sum "${CACHE_DIR}/${ASSET}.part" | awk '{print $1}')
  if [ "$expected" != "$actual" ]; then
    echo "sha512 mismatch for ${ASSET}" >&2
    rm -f "${CACHE_DIR}/${ASSET}.part"
    exit 1
  fi
  extract_dir=$(mktemp -d)
  tar -xzf "${CACHE_DIR}/${ASSET}.part" -C "$extract_dir"
  found=$(find "$extract_dir" -type f -path '*/bin/clickhouse' | head -n 1)
  if [ -z "$found" ]; then
    echo "no bin/clickhouse inside ${ASSET}" >&2
    rm -rf "$extract_dir"
    exit 1
  fi
  install -m 0755 "$found" "$BIN"
  rm -rf "$extract_dir" "${CACHE_DIR}/${ASSET}.part"
fi

DATA_DIR=$(mktemp -d "${TMPDIR:-/tmp}/osiris-clickhouse.XXXXXX")
cleanup() { rm -rf "$DATA_DIR"; }
trap cleanup EXIT

echo "ClickHouse ${VERSION} on http://127.0.0.1:8123 (data: ${DATA_DIR})"
cd "$DATA_DIR"
# No config file: the server uses its embedded defaults (user `default`,
# no password), with these overrides.
"$BIN" server -- \
  --path="${DATA_DIR}/" \
  --listen_host=127.0.0.1 \
  --http_port=8123 \
  --tcp_port=9000 \
  --logger.console=1 \
  --logger.level=warning
