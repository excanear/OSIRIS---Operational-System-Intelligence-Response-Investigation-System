# Phase 13a — Packaging and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A SOC analyst installs `osiris-server` and `osiris-agent` from `.deb`/`.rpm`, opens the Console the Server now serves, and sees this host's events with no file edits. Docker images and Kubernetes manifests ship the same software.

**Architecture:** Three small code changes (`--version`, Console static serving, rotation-safe spool with a persisted Server read position), then packaging assets under `deploy/` built by `tools/package/build.sh` inside `almalinux:9`, then a new `package.yml` CI workflow that installs and smoke-tests every artifact.

**Tech Stack:** Rust (axum 0.7, tower-http 0.5 `fs` + `set-header`), cargo-deb, cargo-generate-rpm, systemd, Docker, kind, kubeconform, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-25-phase-13a-packaging-design.md` (approved 2026-11-25). Read it first; section numbers below refer to it.

## Global Constraints

- Package names: `osiris-server` (binaries `osiris-server`, `osiris`), `osiris-agent` (binary `osirisd`). x86_64 only.
- Version = workspace `0.1.0`; a `v*` tag must equal `v` + workspace version or the release job fails.
- License: workspace `license = "Apache-2.0"`; agent package license field `Apache-2.0 AND (BSD-2-Clause OR GPL-2.0-only)`; BPF C sources unchanged (`Dual BSD/GPL`).
- Paths exactly as spec §5.2 table: `/usr/share/osiris/console`, `/usr/share/osiris/{rules,risk,audit}`, `/usr/lib/osiris/bpf`, `/etc/osiris/{server.yaml,agent.yaml,rules/,risk/weights.yaml}`, `/etc/audit/rules.d/osiris.rules`, `/var/lib/osiris` (osiris:osiris 0750), `/var/lib/osirisd` (root 0700, vault at `/var/lib/osirisd/vault`), `/var/spool/osiris` (root:osiris 2750, spool file 0640).
- Server user/group `osiris`; container UID/GID 10001. Server never runs as root (unit or image).
- Packaged API bind `0.0.0.0:8080`; `console_dir: /usr/share/osiris/console`; `spool_cursor_path: /var/lib/osiris/spool.offset`; Agent `spool_max_bytes: 268435456` (256 MiB).
- Build binaries inside `almalinux:9` (glibc 2.34). Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL/Rocky/Alma 9.
- Upgrades never overwrite edited `/etc/osiris/*`, `host_id`, PKI files, or data. `remove` keeps config + data.
- No new runtime dependency beyond glibc + systemd (agent: Recommends auditd/audit). No OpenSSL.
- Existing CI gates unchanged and green: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `tools/check-dep-graph.sh`, console lint/test/build. `osiris-fileutil` stays std-only (no new deps).
- Not in scope: apt/yum repo, GPG signing, image push, arm64, SELinux module, Helm, auto-enrollment.

## Review Focus

1. **Upgrade with an edited config**: `/etc/osiris/server.yaml` edited, then package reinstalled/upgraded → edit kept, service restarted, data intact. Pinned in Task 7 deb-smoke.
2. **Server restart mid-spool**: Server stopped after ingesting N lines, restarted → resumes at line N+1, no re-run of detection on old lines. Pinned in Task 4 `tailer_resumes_from_persisted_cursor_after_restart`.
3. **Rotation while a reader is behind**: Agent rotates while the Server/forwarder is mid-file → rest of the rotated file is read before the new one, nothing lost or duplicated. Pinned in Task 3 `locate_*` + Task 4 `tailer_finishes_rotated_file_before_new_one` and `forwarder_finishes_rotated_file_before_new_one`.
4. **Console route vs API/auth**: unknown `/api/...` path must 404 (not `index.html`); API routes stay behind `auth_gate`; traversal (`/../`, `%2e%2e`, symlink out of `console_dir`) never escapes. Pinned in Task 2.
5. **Pre-existing spool without header after upgrade** (installed by an older build): readers keep working, first rotation doesn't lose the tail. Pinned in Task 3 `legacy_cursor_*`.

---

### Task 1: `--version` and license

**Files:**
- Create: `LICENSE` (Apache-2.0 full text), `NOTICE`
- Create: `crates/osiris-config/src/version.rs`; Modify: `crates/osiris-config/src/lib.rs`
- Modify: `Cargo.toml` (`license = "Apache-2.0"`), `crates/osiris-agent/src/main.rs`, `crates/osiris-server/src/main.rs`, `crates/osiris-cli/src/main.rs`
- Test: `crates/osiris-config/src/version.rs` (unit), `crates/osiris-e2e-tests/tests/version.rs`

**Interfaces:**
- Produces: `osiris_config::version_string(binary: &str) -> String` → `"<binary> 0.1.0"` or `"<binary> 0.1.0 (<sha>)"` when `option_env!("OSIRIS_GIT_SHA")` was set at build time. `tools/package/build.sh` (Task 5) exports `OSIRIS_GIT_SHA`.

- [ ] **Step 1: Write failing tests.** Unit: `version_string_has_binary_and_workspace_version` asserts `version_string("osirisd").starts_with(&format!("osirisd {}", env!("CARGO_PKG_VERSION")))`. E2E `each_binary_prints_version_without_config`: for `osirisd`, `osiris-server`, `osiris`, run `<bin> --version` (use the existing `cli_binary_path()`-style ancestor walk in `osiris-e2e-tests` to find each binary), assert exit 0 and stdout starts with `"<bin> 0.1.0"`; no config file exists at the default path on the test host, so this also proves no config is read.
- [ ] **Step 2: Run** `cargo test -p osiris-config version` and `cargo test -p osiris-e2e-tests --test version` → FAIL.
- [ ] **Step 3: Implement.** `osirisd`/`osiris-server`: if the first arg is `--version` or `-V`, print `version_string(..)` and exit 0 before any config/root work. `osiris`: clap `#[command(version = ...)]` with the same string (use a `static`/`LazyLock` or `clap::crate_version!`-equivalent that yields the identical text). `NOTICE`: one paragraph — OSIRIS is Apache-2.0; files under `bpf/` are `Dual BSD/GPL` (the kernel requires a GPL-compatible license for the BPF helpers they call).
- [ ] **Step 4: Run** both tests → PASS; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 5: Commit** `feat(13a): --version on all binaries, Apache-2.0 license`.

### Task 2: Server serves the Console

**Files:**
- Create: `crates/osiris-server/src/console.rs`; Modify: `crates/osiris-server/src/lib.rs`, `crates/osiris-server/src/config.rs`, `crates/osiris-server/src/main.rs`
- Modify: `Cargo.toml` (tower-http features `["cors", "fs", "set-header"]`)
- Test: `crates/osiris-server/src/console.rs` (tests module, `tower::ServiceExt::oneshot`)

**Interfaces:**
- Produces: `ServerConfig.console_dir: Option<String>` (serde default `None`).
- Produces: `pub fn attach_console(app: axum::Router, console_dir: Option<&std::path::Path>, tls: bool) -> axum::Router` — returns `app` unchanged when `None` or when the dir lacks `index.html` (then `tracing::warn!` naming the path, run API-only — spec §5.1 *ruling:* status reporting of this condition is a log warning only; the Server has no degraded-component registry to report into).
- Wiring: in `main.rs`, call `attach_console` on the router **after** `.layer(auth_gate)` and before `apply_dev_cors`, so Console files are served without auth while every API route stays gated. Implement as `.fallback_service(..)` so registered routes keep precedence.

Behaviour (spec §5.1):
- Request path starting with `/api/` that reaches the fallback → `404` with an empty/JSON body, never `index.html`.
- `GET`/`HEAD`: serve the file from `console_dir` via `tower_http::services::ServeDir` with `.not_found_service(ServeFile::new(dir/index.html))` (SPA fallback). Other methods → 405.
- Symlinks: canonicalize `console_dir` at startup; reject (404) any resolved file whose canonical path is outside it. *(If `ServeDir` cannot enforce this, wrap it with a check.)*
- Headers on every Console response: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; `Cache-Control: no-cache` for `index.html` (including SPA fallback), `public, max-age=31536000, immutable` under `/assets/`. HSTS comes from the existing `with_hsts` when `tls` is true — do not add a second one.

- [ ] **Step 1: Write failing tests** (temp dir with `index.html` containing `OSIRIS-INDEX`, `assets/app-abc.js`, and on unix a symlink `leak -> <outside file>`):
  - `root_serves_index_with_security_headers`: `GET /` → 200, body contains `OSIRIS-INDEX`, CSP header equals the exact string above, `x-frame-options: DENY`, `cache-control: no-cache`.
  - `deep_link_falls_back_to_index`: `GET /alerts/123` → 200 `OSIRIS-INDEX`.
  - `asset_is_cacheable`: `GET /assets/app-abc.js` → 200, `cache-control` contains `immutable`.
  - `unknown_api_path_is_404_not_index`: `GET /api/v1/nope` → 404, body lacks `OSIRIS-INDEX`.
  - `api_routes_keep_precedence_and_auth`: router with a gated `/api/v1/secret` (wrap with a test middleware returning 401) + console → `GET /api/v1/secret` is 401.
  - `traversal_is_refused`: `GET /../Cargo.toml`, `GET /%2e%2e/%2e%2e/etc/passwd`, `GET /assets/..%2f..%2fsecret` → never 200 with outside content.
  - `#[cfg(unix)] symlink_out_of_console_dir_is_404`.
  - `post_is_405`.
  - `missing_index_runs_api_only`: dir without `index.html` → `GET /` is 404 (router unchanged).
  - Config: `console_dir_is_optional_and_parses` in `config.rs` tests.
- [ ] **Step 2: Run** `cargo test -p osiris-server console` → FAIL.
- [ ] **Step 3: Implement** `console.rs` and the wiring.
- [ ] **Step 4: Run** `cargo test -p osiris-server` → PASS. Then `cd console && npm run build`, run the server locally with `console_dir: console/dist` and a fresh users DB, open `/` in a browser (or Playwright), log in with the bootstrap admin, confirm the Overview loads, Live Events connects, and the browser console shows **no CSP violations**. If the build needs a CSP relaxation, change the CSP constant and its test together and note why in the commit.
- [ ] **Step 5: Commit** `feat(13a): server serves the console build from console_dir`.

### Task 3: Spool identity, rotation and cursor primitives

**Files:**
- Create: `crates/osiris-fileutil/src/spool.rs`; Modify: `crates/osiris-fileutil/src/lib.rs`
- Modify: `crates/osiris-bus/src/sink.rs` (`SpoolFileSink`), `crates/osiris-agent/src/config.rs` (`spool_max_bytes`), `crates/osiris-agent/src/main.rs` (pass it)
- Test: unit tests in both files

Design (spec §5.2b; portable — no inode APIs, so it tests on Windows): each spool file begins with a header line `{"osiris_spool":"<uuid>"}`. The id identifies the file across renames. Rotation renames `<spool>` → `<spool>.1` (replacing it) and starts a new file with a new header. Readers persist `(id, offset)`.

**Interfaces:**
- Produces (in `osiris_fileutil::spool`):
  - `pub fn header_line(id: &str) -> String` → `{"osiris_spool":"<id>"}\n`
  - `pub fn is_header_line(line: &[u8]) -> bool`
  - `pub fn read_spool_id(path: &Path) -> std::io::Result<Option<String>>` — `None` if the file is missing, empty, or its first line is not a header (legacy file).
  - `pub fn rotated_path(spool: &Path) -> PathBuf` → `<spool>.1`
  - `#[derive(Debug, Clone, Default, PartialEq, Eq)] pub struct SpoolCursor { pub id: Option<String>, pub offset: u64 }` with `pub fn load(path: &Path) -> SpoolCursor` (file text `"<id> <offset>"`; a bare number = legacy `{id: None, offset}`; missing/garbled = default) and `pub fn store(&self, path: &Path) -> std::io::Result<()>` (write tmp + `sync_all` + rename, as `osiris-transport`'s `store_offset` does today).
  - `#[derive(Debug, PartialEq, Eq)] pub enum SpoolPosition { Current { offset: u64 }, Rotated { offset: u64 }, Lost }`
  - `pub fn locate(spool: &Path, cursor: &SpoolCursor) -> std::io::Result<SpoolPosition>` — rule: if `cursor.id == read_spool_id(spool)` → `Current`; else if `cursor.id == read_spool_id(rotated_path(spool))` (and `.1` exists) → `Rotated`; else → `Lost`. `None == None` counts as a match (legacy files).
- Produces (in `osiris_bus`): `SpoolFileSink::open_with(path, max_bytes: Option<u64>) -> Result<Self, SinkError>`; `open(path)` = `open_with(path, None)`. Writes a header (uuid v7) when the file is new or empty. On `send`, if `max_bytes` is set and `current_len + line.len() > max_bytes` and the file holds at least one event, rotate first (under the existing lock). On unix, create files with mode `0o640`.
- Produces: `AgentConfig.spool_max_bytes: Option<u64>` (serde default `None` = never rotate).

- [ ] **Step 1: Write failing tests.**
  - spool.rs: `header_round_trips`, `legacy_file_has_no_id`, `cursor_store_load_round_trips`, `cursor_loads_legacy_bare_offset`, `cursor_garbled_is_default`, `locate_current_when_ids_match`, `locate_rotated_when_cursor_matches_dot1`, `locate_lost_when_neither_matches`, `legacy_cursor_on_legacy_file_is_current`, `legacy_cursor_after_first_rotation_is_rotated` (current has header, `.1` has none, cursor id `None` → `Rotated`).
  - sink.rs: `new_spool_starts_with_header`, `existing_legacy_spool_gets_no_header_prepended` (never rewrites existing bytes), `rotates_when_next_line_would_exceed_max` (max = header + 2 lines; third send → `.1` holds header₁ + 2 events, current holds header₂ (different id) + 1 event), `rotation_replaces_previous_dot1`, `#[cfg(unix)] spool_files_are_0640`.
  - config.rs: `spool_max_bytes_defaults_to_none_and_parses`.
- [ ] **Step 2: Run** `cargo test -p osiris-fileutil spool`, `cargo test -p osiris-bus sink`, `cargo test -p osiris-agent spool_max` → FAIL.
- [ ] **Step 3: Implement.** `osiris-fileutil` must stay std-only: build/parse the header with string formatting, not serde (the id is a uuid string the sink supplies). The sink keeps the current length in memory after open (stat once) to avoid a stat per send.
- [ ] **Step 4: Run** the three test commands → PASS; `tools/check-dep-graph.sh` on CI later (it is a no-op on Windows).
- [ ] **Step 5: Commit** `feat(13a): spool header, size-capped rotation and reader cursor`.

### Task 4: Rotation-aware readers (Server tailer persists its cursor; forwarder follows rotation)

**Files:**
- Create: `crates/osiris-fileutil/src/spool_tailer.rs`; Modify: `crates/osiris-fileutil/src/lib.rs`
- Modify: `crates/osiris-server/src/ingest.rs` (`run_ingestion_context_loop`), `crates/osiris-server/src/config.rs` (`spool_cursor_path`), `crates/osiris-server/src/main.rs`
- Modify: `crates/osiris-transport/src/client.rs` (`load_offset`/`store_offset`/`read_batch` → cursor + rotation)
- Test: unit tests in `spool_tailer.rs` and `client.rs`; one in `ingest.rs`

**Interfaces:**
- Consumes: Task 3's `SpoolCursor`, `locate`, `SpoolPosition`, `rotated_path`, `is_header_line`.
- Produces: `pub struct SpoolTailer` in `osiris_fileutil::spool_tailer`:
  - `pub fn new(spool: impl Into<PathBuf>, cursor_path: Option<PathBuf>) -> Self` (loads the cursor when `Some`; `None` = in-memory, today's behaviour).
  - `pub fn poll(&mut self) -> std::io::Result<Vec<String>>` — complete lines (header lines dropped), same partial-line and bounded-read rules as `LineTailer::poll`. On `Rotated`, returns the rest of `.1` first; once `.1` is drained, switches to the current file at offset 0 in the same or next poll. On `Lost`, `tracing`-free (fileutil has no tracing dep): increments `lost_rotations()` and restarts the current file at 0. A current file shorter than the offset → restart at 0 (existing truncation rule).
  - `pub fn commit(&self) -> std::io::Result<()>` — stores the cursor if a `cursor_path` was given.
  - `pub fn lost_rotations(&self) -> u64`.
- Produces: `ServerConfig.spool_cursor_path: Option<String>`; `run_ingestion_context_loop` takes `cursor_path: Option<PathBuf>`, uses `SpoolTailer`, calls `commit()` after each `context.ingest(..)` (success or failure — preserves today's "offset already advanced" semantics), and logs `warn!` when `lost_rotations()` increases. Update every caller (`run_ingestion_loop` passes `None`).
- Forwarder: persists `SpoolCursor` in the existing `<spool>.offset` path (legacy bare number still loads); before each `read_batch`, `locate()` decides the file; draining `.1` then switching resets offset to 0 with the new id; header lines are skipped silently (no "unparsable" warn); `Lost` → `tracing::warn!` and restart current at 0.

- [ ] **Step 1: Write failing tests.**
  - spool_tailer.rs: `tailer_skips_header_lines`, `tailer_resumes_from_persisted_cursor_after_restart` (write header + 3 lines, poll + commit, drop, append 2, new tailer with same cursor path → exactly the 2 new lines), `tailer_finishes_rotated_file_before_new_one` (poll 1 of 3 lines; rotate via `SpoolFileSink` with a small max, write 2 more → next polls return the 2 remaining old lines then the new lines, in order, no duplicates), `tailer_counts_lost_rotation_when_two_rotations_behind`, `tailer_in_memory_mode_without_cursor_path`, `tailer_restarts_on_truncation`.
  - client.rs: `forwarder_cursor_loads_legacy_offset_file`, `forwarder_finishes_rotated_file_before_new_one` (drive `read_batch`/locate directly on files), `forwarder_skips_header_without_warning` (assert the header is not counted as an event).
  - ingest.rs: `ingestion_loop_persists_cursor` (run the loop against a temp spool with `cursor_path`, cancel, assert the cursor file's offset equals the spool length).
- [ ] **Step 2: Run** `cargo test -p osiris-fileutil spool_tailer`, `cargo test -p osiris-transport`, `cargo test -p osiris-server ingest` → FAIL.
- [ ] **Step 3: Implement.** Keep `LineTailer` unchanged (the audit-log tailers still use it).
- [ ] **Step 4: Run** `cargo test --workspace` → PASS (existing e2e tests that tail spools must still pass).
- [ ] **Step 5: Commit** `feat(13a): server spool cursor persists across restarts; readers follow rotation`.

### Task 5: Packaging assets and build script

**Files:**
- Create: `deploy/config/server.yaml`, `deploy/config/agent.yaml`
- Create: `deploy/systemd/osiris-server.service`, `deploy/systemd/osirisd.service`
- Create: `deploy/audit/osiris.rules`, `deploy/audit/osiris-exec-fallback.rules`
- Create: `deploy/package/{server,agent}/{postinst,prerm,postrm}` (deb) and the rpm scriptlets (`deploy/package/{server,agent}/rpm-{post,preun,postun}.sh`)
- Modify: `crates/osiris-server/Cargo.toml`, `crates/osiris-agent/Cargo.toml` (`[package.metadata.deb]`, `[package.metadata.generate-rpm]`; the CLI binary ships inside the server package via the server crate's asset list)
- Create: `tools/package/build.sh`, `tools/package/Dockerfile.build` (almalinux:9 + rustup toolchain from `rust-toolchain.toml` + clang + llvm + nodejs 20 + cargo-deb + cargo-generate-rpm, pinned versions)
- Modify: `docs/operators-response-actions.md` (vault example → `/var/lib/osirisd/vault`)
- Test: `crates/osiris-e2e-tests/tests/packaged_configs.rs`

Contents (spec §5.2–§5.5):
- `server.yaml`: `listen_addr: 0.0.0.0:8080`, `db_path: /var/lib/osiris/events.db`, `spool_path: /var/spool/osiris/spool.ndjson`, `spool_cursor_path: /var/lib/osiris/spool.offset`, `rules_dir: /etc/osiris/rules`, `risk_weights_path: /etc/osiris/risk/weights.yaml`, `console_dir: /usr/share/osiris/console`, every other `*_db_path`/log path under `/var/lib/osiris/`; commented-out `api_tls:` and `agent_listener:` blocks pointing at `docs/operators-api-tls.md` / `docs/operators-agent-transport.md`.
- `agent.yaml` (spec §5.2a): `spool_path: /var/spool/osiris/spool.ndjson`, `spool_max_bytes: 268435456`, `ebpf: {object_dir: /usr/lib/osiris/bpf}`, `audit_log_path`, `fs_audit_log_path`, `identity_audit_log_path`, `systemd_audit_log_path` = `/var/log/audit/audit.log`, `fs_watch_paths`/`persistence_watch_paths` omitted (built-in defaults), `dns_capture: {}` (on, default interface), `k8s_context` left default unless Step 4 shows it logs errors on a plain host (then `enabled: false` with a comment), `status_addr: 127.0.0.1:9200`; commented `forward:` and `control:` blocks, `control.vault_dir: /var/lib/osirisd/vault`.
- `osiris.rules`: only the rule keys the audit-backed identity, systemd and persistence sensors match on (read the sensors' audit parsers for the exact `-k` keys and watched paths; drop `osiris_exec` and `/tmp/osiris-p10`). `osiris-exec-fallback.rules`: the `execve` rules from `tools/real-linux/osiris.rules`, for hosts without eBPF.
- Units: as spec §5.3. Server: `ReadOnlyPaths=/var/spool/osiris`, `ReadWritePaths=/var/lib/osiris`, `StartLimitIntervalSec=60`, `StartLimitBurst=5`, `RestartSec=2`. Agent: `After=network-online.target auditd.service`, `Wants=auditd.service`, no `ProtectHome`.
- Maintainer scripts: as spec §5.4, POSIX `sh`, `set -e`, absolute paths only. Server postinst seeds `/etc/osiris/rules` and `/etc/osiris/risk/weights.yaml` from `/usr/share/osiris/{rules,risk}` **only if absent** (not conffiles — *call:* lets new default rules land under `/usr/share` without dpkg prompts; documented). Agent postinst: `getent group osiris || groupadd --system osiris`; `install -d -m 2750 -o root -g osiris /var/spool/osiris`; `install -d -m 0700 /var/lib/osirisd`; load audit rules with `augenrules --load` when present, else print the warning; `systemctl daemon-reload; systemctl enable --now osirisd`. Both postinsts print the messages spec §5.4 lists. Upgrade → `systemctl try-restart`. Purge → spec §5.4.
- `build.sh` → `dist/`: export `OSIRIS_GIT_SHA=$(git rev-parse --short HEAD)`; `cargo build --release -p osiris-server -p osiris-agent -p osiris-cli`; `tools/ebpf/build.sh target/bpf`; `(cd console && npm ci && npm run build)`; `cargo deb --no-build -p …`, `cargo generate-rpm -p …`; write `dist/SHA256SUMS`. Runs inside `Dockerfile.build` (script `tools/package/build-in-container.sh` does `docker build` + `docker run -v $PWD:/src`).

- [ ] **Step 1: Write failing test** `packaged_configs_load` (runs on any OS): `ServerConfig::load("deploy/config/server.yaml")` and the agent's config loader on `deploy/config/agent.yaml` succeed; assert `console_dir == Some("/usr/share/osiris/console")`, `spool_cursor_path == Some("/var/lib/osiris/spool.offset")`, agent `spool_max_bytes == Some(268435456)`, `ebpf.object_dir == "/usr/lib/osiris/bpf"`, and both `spool_path`s equal `/var/spool/osiris/spool.ndjson`. Also `exec_fallback_rules_are_not_in_default_rules`: `deploy/audit/osiris.rules` contains no `execve` and no `osiris-p10`.
- [ ] **Step 2: Run** `cargo test -p osiris-e2e-tests --test packaged_configs` → FAIL.
- [ ] **Step 3: Write the assets, metadata and scripts.** `shellcheck` every script (CI installs it in Task 7).
- [ ] **Step 4: Build locally in WSL2/Docker** if available (`tools/package/build-in-container.sh`), `dpkg-deb -c` both `.deb`s and check every §5.2 path; otherwise leave it to Task 7's CI run. Run the test → PASS.
- [ ] **Step 5: Commit** `feat(13a): deb/rpm packaging, systemd units, production audit rules`.

### Task 6: Container images and Kubernetes manifests

**Files:**
- Create: `deploy/docker/Dockerfile.server`, `deploy/docker/Dockerfile.agent`, `.dockerignore`
- Create: `deploy/kubernetes/{namespace,server-configmap,server-deployment,server-service,server-pvc,agent-configmap,agent-daemonset,agent-rbac,kustomization}.yaml`
- Create: `deploy/kubernetes/README.md` (short: apply order, per-node PKI provisioning, the enrollment limit — spec §5.7)

Contents:
- Both Dockerfiles: builder stage `FROM` the Task 5 build image (same toolchain), runtime `debian:12-slim` pinned by digest. Server: `useradd --system --uid 10001 osiris`, `USER 10001:10001`, copies binaries, Console, `/usr/share/osiris/{rules,risk}` and a baked `/etc/osiris/server.yaml` (same as `deploy/config/server.yaml` but `spool_path` unused — set `agent_listener` commented, `rules_dir: /usr/share/osiris/rules`), `VOLUME /var/lib/osiris`, `EXPOSE 8080 9443`, `ENTRYPOINT ["/usr/bin/osiris-server", "/etc/osiris/server.yaml"]`. Agent: `osirisd` + BPF objects + `agent.yaml` with a `forward:` block reading `/etc/osiris/{ca.pem,agent.pem,agent.key}`, root.
- Server Deployment: 1 replica, `strategy: Recreate`, `securityContext: runAsNonRoot, runAsUser 10001, fsGroup 10001, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities.drop [ALL]`, readiness/liveness `GET /api/v1/health`, PVC at `/var/lib/osiris`, ConfigMap mounted at `/etc/osiris/server.yaml`, Secret `osiris-server-tls` (optional) for the agent listener.
- Agent DaemonSet: `hostPID`, `hostNetwork`, `dnsPolicy: ClusterFirstWithHostNet`, privileged, mounts `/proc` → `/host/proc` read-only, `/sys/kernel/tracing`, `/sys/kernel/debug`, `/sys/fs/bpf`, `/var/log/audit` read-only, `/etc/osiris` hostPath `DirectoryOrCreate`, `/var/spool/osiris` hostPath. `agent-rbac.yaml`: read-only access the 8e K8s-context collector needs (read `crates/osiris-k8s-context` / `crates/osiris-agent/src/k8s.rs` for the exact resources; it talks to the kubelet — grant `nodes/proxy`/`pods` get/list only if the code needs them).

- [ ] **Step 1: Validate** locally if Docker is available: `docker build -f deploy/docker/Dockerfile.server .` then `docker run --rm <img> --version`; `kubeconform -strict -summary deploy/kubernetes/*.yaml`. Otherwise this is proven by Task 7.
- [ ] **Step 2: Commit** `feat(13a): server/agent images and kubernetes manifests`.

### Task 7: CI workflow `package.yml` and release job

**Files:**
- Create: `.github/workflows/package.yml`, `tools/package/smoke-deb.sh`, `tools/package/smoke-rpm.sh`, `tools/package/smoke-image.sh`, `tools/package/smoke-k8s.sh`

Jobs (spec §7), triggers `push: branches: [ci/**]`, `push: tags: [v*]`, `workflow_dispatch`:
1. `build` (ubuntu-24.04): `tools/package/build-in-container.sh`; `shellcheck` on `deploy/package/**` and `tools/package/*.sh`; upload `dist/`.
2. `deb-smoke` matrix `ubuntu-22.04`, `ubuntu-24.04` (needs build): `smoke-deb.sh` asserts, in order, failing with a clear message per step: `sudo apt-get install -y auditd ./dist/osiris-server_*.deb ./dist/osiris-agent_*.deb`; `systemctl is-active osiris-server osirisd`; `ps -o user= -C osiris-server` = `osiris`; `osiris --version`; `curl -sI /` has the CSP header and body contains the Console's `<div id="root">`; `curl /alerts` returns the same `index.html`; `curl /api/v1/health` is JSON; bootstrap password parsed from `journalctl -u osiris-server`; `osiris login` with it (CLI non-interactive input — use whatever the CLI accepts, e.g. stdin/env; if it has none, log in via `curl POST /api/v1/auth/login`); run `/usr/bin/true` with a unique argv marker and poll `/api/v1/events` (60 s) for an event from this host containing the marker; `sudo systemctl restart osiris-server` then assert `/var/lib/osiris/spool.offset` exists and event count for the marker is still 1; append `# smoke-edit` to `/etc/osiris/server.yaml`, reinstall the same `.deb`s with `apt-get install --reinstall`, assert the edit is kept and services active; `apt-get remove` both → units inactive, `/var/lib/osiris/events.db` still present; `apt-get purge` → `/var/lib/osiris` gone.
3. `rpm-smoke` (container `rockylinux:9`): `dnf install -y ./dist/*.rpm`; all three `--version`; `runuser -u osiris -- /usr/bin/osiris-server /etc/osiris/server.yaml &` (no systemd in the container; create dirs the scriptlets would if `%post` skipped systemd steps), then `curl /` and `/api/v1/health`. Also container `debian:12`: `apt-get install ./dist/*.deb` with `policy-rc.d` blocking service start, then the three `--version`.
4. `image-smoke`: build both images; `docker run -d -p 8080:8080` server; assert `docker exec … id -u` = `10001`, `curl /` and `/api/v1/health`; `docker run --rm osiris-agent osirisd --version`.
5. `k8s-smoke`: install kind (pinned) + kubeconform (pinned); `kubeconform -strict`; `kind load docker-image` both; `kubectl apply -k deploy/kubernetes`; wait for the server Deployment Available (180 s) and `kubectl port-forward` → `curl /`; agent DaemonSet pod `Running` (forwarding not asserted — spec §7).
6. `release` (tags only, needs all smoke jobs): fail unless `${GITHUB_REF_NAME#v}` equals the workspace version from `cargo metadata`; `gh release create` (or upload to the existing one) with `dist/*.deb dist/*.rpm dist/SHA256SUMS`; `permissions: contents: write` on this job only.

- [ ] **Step 1: Push** the branch to `ci/t13a-1` (project convention; `ci.yml` + `package.yml` both trigger) and watch the runs.
- [ ] **Step 2: Fix failures** found by the smoke jobs in the owning task's files (each fix with a regression test where it is code); repeat `ci/t13a-N` until green. Record run ids.
- [ ] **Step 3: Commit** `ci(13a): package build and install smoke tests, tagged releases`.

### Task 8: Operator documentation and roadmap

**Files:**
- Create: `docs/operators-packaging.md`
- Modify: `docs/ROADMAP-REMAINING.md` (13a done + debts), `ARCHITECTURE.md` (one status paragraph in §24 or §29 pointing to `deploy/` and the doc), `README.md` (minimal: what OSIRIS is, install in three commands, link to the doc — the full README is 13b)

`operators-packaging.md` covers: supported distros; install (deb, rpm); what lives where (spec §5.2 table, with the actual final paths); first login (journal bootstrap password); default sensors and audit rules (and when to load `osiris-exec-fallback.rules`); spool rotation and `spool.offset`; upgrade / remove / purge behaviour per format; multi-host (agent-only install, `forward:` + `agent_listener:` with `osiris pki`, link to the 9a doc); Docker run flags; Kubernetes apply + per-node PKI; known gaps (SELinux unconfined agent, arm64, no repo/signing, K8s enrollment, duplicate alerts on genuine resend).

- [ ] **Step 1: Write the docs.** Every command shown must match what Task 7's smoke scripts actually run.
- [ ] **Step 2: Commit** `docs(13a): packaging operator guide, roadmap update`.
