# Phase 13a — Packaging and deployment (design)

Status: design. Marked *(call)* = decided by the assistant under the user's instruction to
proceed with the recommended option; everything else comes from the user, `ARCHITECTURE.md`
or `docs/ROADMAP-REMAINING.md` ("Fase 13 — Produto e documentação").

## 0. Phase split *(call)*

Phase 13 is three independent blocks, done in this order:

- **13a (this document):** packaging and deployment — `.deb`/`.rpm`, systemd units,
  Dockerfiles, Kubernetes manifests, the Server serving the built Console, a license.
- **13b:** documentation — README, end-to-end install and operations guide, architecture
  summary, ADR-001..009 (indexed in `ARCHITECTURE.md` §28, never filed), updated threat
  model, incident-response guide.
- **13c:** Console — Audit screen, real pagination, the "Phase 13 UX debt" list in
  `docs/VALIDATION.md`.

13a goes first because 13b's install guide documents what 13a ships, and an analyst cannot
use 13c's screens before they can install the product.

## 1. Intent and why

**User:** the target user is a SOC analyst installing OSIRIS on Linux servers.

Today nobody but a developer can run OSIRIS. You need a Rust toolchain, clang for the BPF
objects, Node to run the Console under Vite, hand-written YAML at the paths `main.rs`
hard-codes (`/etc/osiris/agent.yaml`, `/etc/osiris/server.yaml`), and you have to start
both daemons by hand. The Server does not serve the Console at all.

**Success:** on a supported server an analyst runs `apt install ./osiris-server_*.deb
./osiris-agent_*.deb` (or `dnf install` with the `.rpm`), gets the bootstrap admin
password with `journalctl -u osiris-server`, opens `http://<host>:8080/` in a browser,
logs in, and sees events from that host within a minute, without editing any file. Upgrades
keep their config and data. Removing the packages leaves no running services. Docker and
Kubernetes users get the same software from an image and from manifests in the repo.

## 2. Goals, non-goals, anti-goals

**Goals**
1. `osiris-server` serves the production Console build (`console/dist`) from a configurable
   directory, with SPA fallback, on the same listener as the API.
2. Two native packages per format (`.deb`, `.rpm`), x86_64:
   - `osiris-server`: `osiris-server` and `osiris` (CLI) binaries, Console build, default
     rules (`config/rules`) and risk weights (`config/risk`), default `server.yaml`, systemd
     unit, system user/group `osiris`.
   - `osiris-agent`: `osirisd`, the four BPF objects with their sha256 sidecars, default
     `agent.yaml`, audit rules file, systemd unit.
3. Single-host default works out of the box: the Agent writes the spool, the same-host
   Server tails it (the existing default transport). No PKI is needed for this path.
4. Multi-host path is documented and works with the packages: agents get `forward:` and the
   server gets `agent_listener:` by editing config, using the existing `osiris pki`
   commands (Phase 9a). No new enrollment mechanism.
5. Container images: `Dockerfile.server` and `Dockerfile.agent` (multi-stage, reproducible
   from the repo), server image runs non-root.
6. Kubernetes manifests under `deploy/kubernetes/`: Server (Deployment + Service + PVC +
   ConfigMap) and Agent DaemonSet.
7. CI proves all of it on every `ci/**` push and on `v*` tags (§7).
8. `LICENSE` (Apache-2.0) at the repo root and `license = "Apache-2.0"` in the workspace
   `Cargo.toml` (today `UNLICENSED`). *(call: the user deferred the license choice to the
   recommendation)* The BPF C sources stay `Dual BSD/GPL` (the kernel requires a
   GPL-compatible license for the helpers they use); a `NOTICE` file says so, and the agent
   package's license field is `Apache-2.0 AND (BSD-2-Clause OR GPL-2.0-only)`. *(call)*
9. `--version` on `osirisd`, `osiris-server` and `osiris` (needed by package smoke tests and
   by support: "which version are you on?").

**Non-goals (later or never in 13a)**
- Hosting an apt/yum repository, GPG-signing packages, publishing images to a registry.
  A tag build attaches the packages and a `SHA256SUMS` file to the GitHub release; images
  are built and smoke-tested but not pushed. *(call)*
- arm64 packages (the kprobe objects are x86_64-only, roadmap 11b-3/11b-4 debts).
- An SELinux policy module. RPMs install and run on RHEL-like 9 with SELinux enforcing, with
  the Agent unconfined as root; a known gap documented in the packaging doc.
- A Helm chart, an operator, or automated certificate enrollment for the DaemonSet.
- The full install/operations guide (13b). 13a ships only `docs/operators-packaging.md`:
  what each package installs where, the unit names, upgrade/remove behaviour, and the
  multi-host and Kubernetes steps.
- ClickHouse in the packages or manifests (it stays opt-in, `docs/operators-clickhouse.md`).

**Anti-goals (failure even if it "works")**
- A package that overwrites an edited `/etc/osiris/*.yaml` on upgrade, or deletes
  `/var/lib/osiris` on `remove` (only `purge` / never for rpm `erase` of data).
- A Server unit running as root, or a Server container running as root.
- The Console served with permissive headers: the Console route must not weaken the API's
  existing security headers or CORS behaviour (Phase 9b: HSTS when TLS is on).
- Binaries that only run on the CI runner's glibc (e.g. built on Ubuntu 24.04 and failing on
  RHEL 9).
- Installing the packages silently changes the host's audit configuration in a way the
  analyst can't see: the audit rules file is installed and loaded, and the postinst prints
  that it did so.

## 3. Constraints (found in the code)

- Config paths are hard-coded defaults in `main.rs` (`/etc/osiris/agent.yaml`,
  `/etc/osiris/server.yaml`, first CLI arg overrides). Default DB paths already point at
  `/var/lib/osiris/*` (e.g. `hosts.db`, `baseline.db`, vault `/var/lib/osiris/vault`).
- Host identity is created at `/etc/osiris/host_id` by the Agent on first run (it must not
  be in a package payload, and must survive upgrades).
- The Server creates a one-time bootstrap admin when the users DB is new and logs its
  password once (`osiris-server/src/main.rs`, "created a bootstrap admin user"). The package
  relies on that; the postinst tells the analyst to read it from the journal.
- TLS is rustls everywhere (no OpenSSL runtime dependency); the only native runtime
  dependency is glibc.
- BPF objects are built by `tools/ebpf/build.sh <dir>` (clang, CO-RE) with sha256 sidecars;
  the Agent loads them from a configured object directory and falls back to audit/procfs if
  missing.
- The Agent needs root (eBPF, audit netlink, AF_PACKET). The Server needs no privilege
  beyond binding 8080 (and 9443 if `agent_listener` is on).
- The Agent's sensors need auditd present for the audit backends/fallback;
  `tools/real-linux/osiris.rules` is the rules file the real-Linux suite loads.
- The Console is a Vite app (`console/`, `npm run build` → `console/dist`). Its API client
  must work same-origin (no dev proxy) when served by the Server.

## 4. Approaches (chosen: A)

- **A. Native packages first, containers second (chosen).** `.deb`/`.rpm` with systemd
  units and FHS paths; Dockerfiles and manifests as the second install path. Matches how a
  SOC analyst operates a Linux server (`apt`/`dnf`, `systemctl`, `journalctl`), and the
  Agent's needs (root, host audit, host eBPF) fit a native service best.
- B. Container-first (compose for everything). Rejected: the Agent in a container needs host
  PID, host audit and privileged mode, the exact setup that broke under WSL2's child PID
  namespace in Phase 10; and it's not how this user runs servers.
- C. Tarball + `install.sh`. Rejected: no upgrades, no clean removal, no package-manager
  integration, and less trustworthy for a security product.

## 5. Design

### 5.1 Server serves the Console
- New optional `server.yaml` key `console_dir` (path). Unset = today's behaviour (API only).
  The packaged `server.yaml` sets `console_dir: /usr/share/osiris/console`.
- Routing: `/api/*` (and any other existing non-Console route, e.g. WebSocket and health
  endpoints) keep their handlers and precedence; any other `GET`/`HEAD` serves a file from
  `console_dir`, falling back to `index.html` for unknown paths (client-side routes).
  Path traversal must be impossible (use a vetted static-file service; test `..`, encoded
  `%2e%2e`, and absolute-path requests).
- Headers on Console responses: a `Content-Security-Policy` restricting scripts, styles and
  connections to `'self'` (plus `ws:`/`wss:` self for live events), `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (or `frame-ancestors
  'none'`), and HSTS when TLS is on (as the API does). Hashed assets cacheable long-term,
  `index.html` `no-cache`.
- Startup: if `console_dir` is set but missing or lacks `index.html`, log a warning and run
  API-only (not a fatal error), and show it in the Server's health/status the way other
  degraded components are shown. *(call)*
- Console build: confirm the API client uses relative URLs same-origin; fix if it assumes
  the dev proxy.

### 5.2 Package layout *(call: FHS, matching the paths the code already defaults to)*

| Path | Package | Notes |
|---|---|---|
| `/usr/bin/osiris-server`, `/usr/bin/osiris` | server | |
| `/usr/bin/osirisd` | agent | |
| `/usr/share/osiris/console/` | server | Console build |
| `/usr/share/osiris/rules/`, `/usr/share/osiris/risk/` | server | shipped defaults (overwritten on upgrade) |
| `/usr/lib/osiris/bpf/*.bpf.o` + sha256 | agent | |
| `/etc/osiris/server.yaml` | server | conffile |
| `/etc/osiris/agent.yaml` | agent | conffile |
| `/etc/osiris/rules/`, `/etc/osiris/risk/weights.yaml` | server | conffiles seeded from the defaults; operator-edited |
| `/etc/audit/rules.d/osiris.rules` | agent | conffile |
| `/var/lib/osiris/` | server (created) | owned `osiris:osiris` 0750, all Server DBs and `spool.offset` |
| `/var/lib/osirisd/` | agent (created) | root 0700; Agent state, `vault/` |
| `/etc/audit/rules.d/osiris.rules` source | agent | `deploy/audit/osiris.rules` (production set, §5.2a) |
| `/var/spool/osiris/` | agent (created) | root:osiris 0750; spool file readable by group `osiris` |
| `/usr/lib/systemd/system/osiris-server.service`, `osirisd.service` | | |

Shipped `server.yaml` keeps the API bound to `0.0.0.0:8080` *(call: the analyst opens the
Console from their workstation; loopback-only would fail the success criterion)*, with the
packaging doc and the postinst message pointing at `docs/operators-api-tls.md` to turn on
TLS. Rules dir: `/etc/osiris/rules` (operator-owned copy) — the builder decides whether the
package seeds it by conffiles or by postinst copy-if-absent, as long as upgrades never
overwrite edited rules.

The Server must be able to read the Agent's spool when both run on one host as different
users: the spool file must be created group-readable by `osiris` (directory setgid
`osiris`, file mode 0640). If the Agent today creates it 0600, change that behind a config
option or for the spool directory specifically; do not make it world-readable.

**Agent vault** *(call, from the builder check)*: the quarantine vault is Agent data
(`control.vault_dir`, root 0700), so the packaged `agent.yaml` sets
`vault_dir: /var/lib/osirisd/vault`, not `/var/lib/osiris/vault`. `/var/lib/osiris` holds
Server data only; each package's purge deletes only its own directory. Docs and examples
that show `/var/lib/osiris/vault` are updated.

### 5.2a Shipped `agent.yaml` and audit rules *(call, from the builder check)*
Goal: useful signal out of the box without heavy audit load or duplicate data.
- `ebpf` on, pointing at `/usr/lib/osiris/bpf` (process, network, filesystem, DNS
  attribution); audit/procfs stay the automatic fallbacks.
- `fs_watch_paths`: the built-in default list. `persistence_watch_paths`: the built-in
  defaults. `dns_capture`: on. `k8s_context`: left at its default (it already degrades
  quietly off-cluster — builder verifies and turns it off in the packaged file if it logs
  errors on a plain server).
- Audit log inputs (`audit_log_path` and the identity/systemd variants) on, reading
  `/var/log/audit/audit.log`, because the identity and systemd sensors have audit backends.
- **Production audit rules** replace the Phase 10 test file in the package:
  `deploy/audit/osiris.rules` loads only what the audit-backed sensors need (identity,
  systemd unit and persistence path watches) and **no blanket `execve` rule** and no
  `/tmp/osiris-p10` watch. An exec fallback file `osiris-exec-fallback.rules` ships in
  `/usr/share/osiris/audit/`, not loaded; the packaging doc says when to install it (eBPF
  unavailable). `tools/real-linux/osiris.rules` stays as the test suite's file.
- The CI "event within 60 s" check uses an exec seen by the eBPF backend (it works on the
  GitHub runners, Phase 11b).

### 5.2b Spool lifecycle *(call, from the builder check)*
Today the spool only grows (`SpoolFileSink` appends forever) and the Server's same-host
tailer keeps its position in memory, so every Server restart — including the one every
upgrade does — re-reads the whole spool: events dedupe (`INSERT OR IGNORE`), but detection,
risk, exporters and plugins run again, and startup slows as the file grows. A packaged,
always-on install makes both real, so 13a fixes them:
- **Server read position persisted**: the tailer stores (file identity, offset) in
  `/var/lib/osiris/spool.offset` after each committed batch, and resumes from it. A
  different file identity, or a file shorter than the offset, restarts at 0 (existing
  truncation rule).
- **Size-capped rotation in the Agent**: new `spool_max_bytes` (packaged default 256 MiB)
  *(call)*; on reaching it the Agent renames the spool to `<spool>.1` (replacing the old
  one) and opens a new file. Both readers (Server tailer and the 9a forwarder with its
  `<spool>.offset`) must, on seeing a new file identity, finish reading the rotated file
  from their saved offset before switching, so a reader that is less than one file behind
  loses nothing. A reader more than one file behind loses the oldest data, counted and
  logged. No logrotate config *(the Agent owns rotation)*.
- Duplicate alerts on a genuine resend remain the existing 12a/12b debt; this change only
  removes the restart-driven re-read.

### 5.3 systemd units
- `osiris-server.service`: `User=osiris`, `Group=osiris`, `StateDirectory=osiris`,
  `ExecStart=/usr/bin/osiris-server /etc/osiris/server.yaml`, `Restart=on-failure`,
  hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`,
  `PrivateDevices`, empty `CapabilityBoundingSet`, `ReadWritePaths=/var/lib/osiris`,
  read access to `/var/spool/osiris`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
  `SystemCallFilter=@system-service`). The exact set is the builder's, verified by the CI
  smoke test (the Server must still start, tail, serve and export).
- `osirisd.service`: runs as root; `Restart=on-failure`; only hardening that does not break
  the sensors (e.g. `ProtectHome=read-only` would blind the filesystem sensor under `/home` —
  do not add it). `After=auditd.service`, `Wants=auditd.service`.
- Both: `Type=simple` *(call; neither daemon implements sd_notify)*, logs to the journal
  (stdout/stderr, existing `tracing` output).

### 5.4 Maintainer scripts
- Server install: create system user/group `osiris` if absent, create `/var/lib/osiris`,
  `systemctl daemon-reload`, enable and start `osiris-server`, print: Console URL,
  `journalctl -u osiris-server | grep -i "bootstrap admin"`, and the TLS doc pointer.
- Agent install: create group `osiris` if absent (the agent may be installed alone on a
  remote host), create dirs, load the audit rules if `augenrules` exists (print that it
  did; print a warning if auditd is absent, not an error), enable and start `osirisd`.
- Upgrade: restart services; never touch `/etc/osiris/*.yaml`, `host_id`, data or PKI.
- Remove: stop and disable services; keep config and data.
- Debian `purge` *(call)*: deletes the package's state dirs (`/var/lib/osiris` for the
  server, `/var/lib/osirisd` and `/var/spool/osiris` for the agent) and its conffiles; the
  agent purge also deletes the Agent-created `/etc/osiris/host_id` (a re-install becomes a
  new host — documented). PKI files the operator placed (`*.pem`, `*.key`) are never
  deleted. The `osiris` user/group is left in place (Debian convention).
- RPM erase keeps data (rpm has no purge); documented.
- Dependencies: server — none beyond glibc and systemd; agent — `Recommends: auditd`
  (deb) / `Recommends: audit` (rpm).

### 5.5 Build
- `tools/package/build.sh` builds everything into `dist/`: release binaries, BPF objects
  (`tools/ebpf/build.sh`), `npm ci && npm run build` for the Console, then `.deb` and
  `.rpm` (tools: `cargo-deb` and `cargo-generate-rpm` *(call)*, with metadata in the three
  binary crates' `Cargo.toml` or a dedicated packaging manifest — builder's choice).
- Binaries are built inside an `almalinux:9` container (glibc 2.34) *(call)* so the same
  binaries run on every supported distro. Package version = workspace version
  (`0.1.0`), with a tag `vX.Y.Z` required to match it.
- Supported distros (documented and smoke-tested where the CI can): Ubuntu 22.04 and 24.04,
  Debian 12 and 13, RHEL/Rocky/AlmaLinux 9.

### 5.6 Containers
- `deploy/docker/Dockerfile.server`: builder stage (same toolchain image as §5.5), runtime
  `debian:12-slim` *(call)* with the server binary, CLI, Console and default rules/risk,
  `USER osiris` (fixed UID/GID 10001), `VOLUME /var/lib/osiris`, `EXPOSE 8080 9443`,
  config at `/etc/osiris/server.yaml` (baked default, mountable).
- `deploy/docker/Dockerfile.agent`: `osirisd` + BPF objects + default agent config; runs
  as root and needs `--privileged --pid=host --net=host` and host mounts — documented, used
  by the DaemonSet. No compose file *(call)*.

### 5.7 Kubernetes (`deploy/kubernetes/`, plain manifests, kustomize-compatible)
- Namespace `osiris`; Server Deployment (1 replica, SQLite on a PVC, so `strategy:
  Recreate`), Service (8080 API/Console, 9443 agent listener), ConfigMap `server.yaml`,
  Secret for server cert/key/CA.
- Agent DaemonSet: `hostPID`, `hostNetwork`, privileged, host mounts for `/proc`, `/sys`
  (bpf, tracing), the host root read-only for path resolution, and `hostPath`
  `/etc/osiris` for `host_id` and the agent's PKI. Agents ship to the Server over the
  Phase 9a mTLS listener (`forward:`), since they are not on the Server's host.
- Enrollment limit (documented, not solved): each agent certificate binds one host UUID,
  so the operator must pre-provision `/etc/osiris/{host_id,agent.pem,agent.key,ca.pem}` on
  each node (config management) before the DaemonSet pod becomes useful. A pod without
  them logs a clear error and stays running without forwarding. Automated enrollment is
  future work.
- The DaemonSet tolerates the K8s context collector added in 8e (it already reads the
  in-cluster API when configured); the manifest includes the read-only RBAC that
  collector needs if it is enabled. *(builder: check what the k8s-context collector needs)*

### 5.8 Version flag
`--version` prints `<binary> <workspace version> (<git short sha if available at build
time>)` for all three binaries; must not require a config file or root.

## 6. Error handling, observability, security
- Missing/invalid config at the packaged path: daemons exit non-zero with the existing
  message; systemd shows it; `Restart=on-failure` with a start-rate limit so a broken config
  doesn't spin.
- Console directory problems: warning + degraded status (5.1), never a crash.
- Security review items: the static-file route (traversal, symlinks out of `console_dir`
  must not be followed outside it, content types), CSP correctness, the unit hardening, the
  postinst running as root (no use of untrusted paths, no `curl | sh`), spool group
  permission, and that images contain no build secrets or toolchains.

## 7. Verification (CI)
New workflow `package.yml`, triggered on `ci/**` pushes, `v*` tags and manual dispatch:
1. **build**: `tools/package/build.sh` in `almalinux:9`; upload `dist/` artifacts.
2. **deb-smoke** (ubuntu-24.04 runner, real systemd, plus ubuntu-22.04): install both
   `.deb`s; both units `active`; `osiris --version`; `GET /` returns the Console
   `index.html` with the CSP header; a deep link (`/alerts`) returns `index.html`;
   `/api/v1/...` still returns JSON; bootstrap password found in the journal; log in with
   it via the CLI; run a command on the host and see an event for this host through the
   API within 60 s; `apt install` the same packages again (upgrade path) with an edited
   `server.yaml` and confirm it is kept; `apt remove` → units gone, data kept.
3. **rpm-smoke** (rockylinux:9 container, no systemd): `dnf install` both rpms; binaries
   run `--version`; `osiris-server` starts as user `osiris` against the packaged config
   and serves `/` and an API route. Debian 12 container: install the `.deb`s and run
   `--version` (glibc compatibility).
4. **image-smoke**: build both images; run the server image as non-root, `GET /` and an
   API route; `docker run osiris-agent osirisd --version`.
5. **k8s-smoke**: kind cluster; `kubeconform` (or `kubectl --dry-run=server`) on the
   manifests; apply; Server pod Ready and serving `/`. Agent pod reaches Running; its
   forwarding is not asserted (no per-node PKI in kind) unless the builder provisions it
   cheaply.
6. On a `v*` tag only: attach `.deb`, `.rpm` and `SHA256SUMS` to the GitHub release.
Existing CI gates (fmt, clippy, tests, dep-graph, console) stay unchanged and must pass;
the new static-file route gets unit/integration tests in the normal test suite.

## 8. Left to the builder
- Exact tooling invocation (cargo-deb/cargo-generate-rpm metadata location), script
  structure, which static-file crate (tower-http `ServeDir` or equivalent).
- The exact systemd hardening set, subject to the CI smoke test.
- How rules/risk defaults seed `/etc/osiris` without overwriting edits.
- Kind specifics, and whether the agent pod's forwarding can be asserted.
- The packaging doc's wording and structure (13b will fold it into the full guide).
