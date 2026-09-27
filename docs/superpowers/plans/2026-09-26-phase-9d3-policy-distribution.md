# Phase 9d-3 — Group Policy Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admins attach a policy (telemetry level, per-sensor on/off, heartbeat interval) to host groups; every member agent converges on its effective policy live, via signed `ApplyPolicy` commands reconciled against the policy hash each heartbeat reports.

**Architecture:** A new pure crate `osiris-policy` owns the model, validation, level→event-type table, resolution and hash. `osiris-command` gains a signed `ApplyPolicy` action. `osiris-fleet` (hosts.db v2) stores group policies, each host's applied hash and delivery state. The agent persists an overlay and applies it live (pipeline filter, sensor manager, heartbeat watch channel). The API exposes policy routes and per-host effective views; a server-side `PolicyReconciler` sends `ApplyPolicy` when desired ≠ applied.

**Tech Stack:** Rust (axum 0.7, rusqlite 0.31, tokio, serde, sha2, hex, ed25519-dalek via osiris-command), clap, React + TypeScript + React Query + Vitest.

**Spec:** `docs/superpowers/specs/2026-09-26-phase-9d3-policy-distribution-design.md`

## Global Constraints

* `KNOWN_SENSORS = ["container", "filesystem", "identity", "network", "persistence", "process_exec", "systemd"]`; unknown sensor → error text `unknown sensor: <name>`.
* Heartbeat range `10..=3600`; error text `heartbeat_interval_secs must be between 10 and 3600`.
* `TelemetryLevel` serializes as `MINIMAL|STANDARD|DETAILED|FORENSIC`; level codes 1..=4; `None` = no policy = allow everything. `ALWAYS_ALLOWED` = `AgentHealth`, `SensorHealth`, `AgentStart`, `AgentStop` — never filtered.
* Level table exactly as spec §3.3 (cumulative), implemented with an exhaustive `match` on `EventType` (no `_ =>`).
* Resolution (spec §3.4): drop tenant groups whose tenant ≠ host's current tenant; order platform tier, then tenant tier; within tier `priority` desc then `group_id` asc; each field (level, each sensor name, heartbeat) independently takes the first definition.
* Hash (spec §3.5): SHA-256 over `b"osiris-policy-v1\0"` + level byte (0 absent, 1..=4) + sensor count u32 BE + each (name len u32 BE, name bytes, enabled u8) in name order + heartbeat (`0u8` | `1u8` + u64 BE). Wire form lowercase hex. The empty policy's hash is the "no policy" value; a heartbeat with `policy_hash: null` or no field means that value.
* `ApplyPolicy` canonical tag `4`; payload encoding = the hash-input field encoding (without the domain tag) followed by the 32 hash bytes. Every payload field is signed.
* hosts.db `SCHEMA_VERSION = 2`; v1→v2 migration in one transaction; `applied_policy_hash` updated under the existing freshness gate.
* Delivery results stored as `EXECUTED|REFUSED|FAILED|OFFLINE|TIMED_OUT`. Host policy status values `IN_SYNC|PENDING|FAILED|UNMANAGED` (spec §4.2 rules). Reconciler backoff 60 s per (host, desired hash); actor `policy-reconciler`; reason `effective policy <first 12 hex>`.
* Routes: `GET|PUT|DELETE /api/v1/groups/:group_id/policy` (GET Viewer, PUT/DELETE Admin), `GET /api/v1/hosts/:host_id/policy` (Viewer). Tenant allowlist: exact shapes only. Platform sources are `{"tier":"PLATFORM"}` for tenant callers. 404 bodies `group not found` / `host not found`; 500 body `internal error`.
* Audit: `group_policy_set` (why = the policy JSON), `group_policy_clear`; success only.
* Agent overlay path `{spool_path}.policy.json`; atomic write (temp → fsync → rename), 0600 on Unix; empty policy deletes the file. Load before sensors start; corrupt → log error, ignore, report `policy_hash: null`.
* Before any commit: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`, `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; console tasks also `npx vitest run` + `npm run build` in `console/`. Run in the foreground to completion.
* Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
* Subagent model `sonnet`. Tasks 2, 5, 6, 7 are security-relevant (signature coverage, agent executor, tenant boundary, reconciler) → review on `opus`.
* Linux-only code (`crates/osiris-agent/src/linux_exec.rs`) must not need changes: `ActionExecutor::apply_policy` has a default body returning `FailCode::Unsupported`.

## Review Focus

1. A tenant Admin's policy reaching a host outside its tenant (host reassigned; host in a platform group) — resolution test `a_stale_tenant_group_is_ignored_and_platform_beats_tenant` (Task 1) and API test `a_tenant_policy_never_applies_to_another_tenants_host` (Task 6).
2. A tampered `ApplyPolicy` (flipped sensor, changed level/heartbeat, swapped hash) — Task 2 test `changing_any_policy_field_breaks_the_signature` and Task 5 test `a_payload_whose_hash_does_not_match_is_refused_without_side_effects`.
3. Level Minimal must still pass heartbeats — Task 1 `always_allowed_types_pass_at_minimal` and Task 4 `minimal_level_drops_file_writes_but_keeps_agent_health`.
4. A refusing agent must not be spammed on every heartbeat — Task 7 `backoff_suppresses_resend_of_the_same_hash_within_60s`.
5. A 9d-2 (v1) hosts.db upgrading in place without losing groups — Task 3 `a_v1_database_migrates_to_v2_keeping_groups_and_members`.

---

### Task 1: `osiris-policy` crate — model, validation, level table, resolution, hash

**Files:**
- Create: `crates/osiris-policy/Cargo.toml`, `crates/osiris-policy/src/lib.rs`

**Interfaces:**
- Consumes: `osiris_schema::EventType`.
- Produces (all `pub`): `KNOWN_SENSORS`, `MIN_HEARTBEAT_SECS = 10`, `MAX_HEARTBEAT_SECS = 3600`, `TelemetryLevel { Minimal, Standard, Detailed, Forensic }` (+ `code() -> u8`, `from_code(u8) -> Option<Self>`), `GroupPolicy { telemetry_level, sensors: BTreeMap<String,bool>, heartbeat_interval_secs: Option<u64>, priority: i32 }` (+ `validate()`), `PolicyError`, `EffectivePolicy { telemetry_level, sensors, heartbeat_interval_secs }` (+ `validate()`, `is_empty()`, `hash() -> [u8;32]`, `hash_hex() -> String`), `encode_fields(level, sensors: &[(&str, bool)], heartbeat) -> Vec<u8>`, `empty_policy_hash_hex() -> String`, `allows(Option<TelemetryLevel>, EventType) -> bool`, `PolicyTier { Platform, Tenant }`, `FieldSource { group_id: Uuid, tier: PolicyTier }`, `GroupPolicyInput { group_id: Uuid, group_tenant: Option<Uuid>, policy: GroupPolicy }`, `ResolvedPolicy { effective, level_source, sensor_sources: BTreeMap<String, FieldSource>, heartbeat_source }`, `resolve(host_tenant: Option<Uuid>, inputs: &[GroupPolicyInput]) -> ResolvedPolicy`.

- [ ] **Step 1: Crate manifest**

```toml
[package]
name = "osiris-policy"
version.workspace = true
edition.workspace = true

[dependencies]
osiris-schema = { path = "../osiris-schema" }
serde = { workspace = true }
thiserror = { workspace = true }
uuid = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }

[dev-dependencies]
serde_json = { workspace = true }
```

If `sha2` is not in `[workspace.dependencies]`, check how another crate (e.g. `osiris-audit`) declares it and copy that line. The root manifest uses a `crates/*` glob, so no workspace-member edit is needed.

- [ ] **Step 2: Write the failing tests** (bottom of `src/lib.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::EventType;

    fn gid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn input(n: u128, tenant: Option<Uuid>, p: GroupPolicy) -> GroupPolicyInput {
        GroupPolicyInput { group_id: gid(n), group_tenant: tenant, policy: p }
    }

    #[test]
    fn levels_are_cumulative() {
        use TelemetryLevel::*;
        assert!(allows(Some(Minimal), EventType::ProcessExec));
        assert!(!allows(Some(Minimal), EventType::NetworkConnect));
        assert!(allows(Some(Standard), EventType::NetworkConnect));
        assert!(!allows(Some(Standard), EventType::FileWrite));
        assert!(allows(Some(Detailed), EventType::FileWrite));
        assert!(allows(Some(Detailed), EventType::ProcessExec));
        assert!(allows(Some(Forensic), EventType::SocketListen));
    }

    #[test]
    fn always_allowed_types_pass_at_minimal() {
        for t in [EventType::AgentHealth, EventType::SensorHealth, EventType::AgentStart, EventType::AgentStop] {
            assert!(allows(Some(TelemetryLevel::Minimal), t), "{t:?}");
        }
    }

    #[test]
    fn no_policy_allows_everything() {
        assert!(allows(None, EventType::FileWrite));
        assert!(allows(None, EventType::SocketCreate));
    }

    #[test]
    fn validation_rejects_unknown_sensors_and_bad_heartbeats() {
        let mut p = GroupPolicy::default();
        p.sensors.insert("dns".into(), true);
        assert_eq!(p.validate(), Err(PolicyError::UnknownSensor("dns".into())));
        assert_eq!(PolicyError::UnknownSensor("dns".into()).to_string(), "unknown sensor: dns");
        let mut p = GroupPolicy::default();
        p.heartbeat_interval_secs = Some(9);
        assert_eq!(p.validate(), Err(PolicyError::HeartbeatOutOfRange));
        assert_eq!(
            PolicyError::HeartbeatOutOfRange.to_string(),
            "heartbeat_interval_secs must be between 10 and 3600"
        );
        p.heartbeat_interval_secs = Some(3601);
        assert!(p.validate().is_err());
        p.heartbeat_interval_secs = Some(10);
        p.sensors.insert("network".into(), false);
        assert_eq!(p.validate(), Ok(()));
        assert_eq!(GroupPolicy::default().validate(), Ok(()));
    }

    #[test]
    fn a_stale_tenant_group_is_ignored_and_platform_beats_tenant() {
        let (a, b) = (Uuid::from_u128(100), Uuid::from_u128(200));
        let tenant_a = GroupPolicy { telemetry_level: Some(TelemetryLevel::Forensic), priority: 1000, ..Default::default() };
        let stale_b = GroupPolicy { heartbeat_interval_secs: Some(10), ..Default::default() };
        let platform = GroupPolicy { telemetry_level: Some(TelemetryLevel::Minimal), priority: -5, ..Default::default() };
        let r = resolve(Some(a), &[input(1, Some(a), tenant_a), input(2, Some(b), stale_b), input(3, None, platform)]);
        assert_eq!(r.effective.telemetry_level, Some(TelemetryLevel::Minimal));
        assert_eq!(r.level_source, Some(FieldSource { group_id: gid(3), tier: PolicyTier::Platform }));
        assert_eq!(r.effective.heartbeat_interval_secs, None, "tenant b's group no longer applies");
    }

    #[test]
    fn priority_orders_within_a_tier_and_ties_break_by_group_id() {
        let t = Some(Uuid::from_u128(100));
        let low = GroupPolicy { telemetry_level: Some(TelemetryLevel::Standard), priority: 1, ..Default::default() };
        let high = GroupPolicy { telemetry_level: Some(TelemetryLevel::Detailed), priority: 5, ..Default::default() };
        assert_eq!(resolve(t, &[input(1, t, low.clone()), input(2, t, high)]).effective.telemetry_level, Some(TelemetryLevel::Detailed));
        let tie_a = GroupPolicy { heartbeat_interval_secs: Some(30), ..Default::default() };
        let tie_b = GroupPolicy { heartbeat_interval_secs: Some(60), ..Default::default() };
        assert_eq!(resolve(t, &[input(9, t, tie_b), input(4, t, tie_a)]).effective.heartbeat_interval_secs, Some(30));
    }

    #[test]
    fn fields_resolve_independently() {
        let t = Some(Uuid::from_u128(100));
        let mut first = GroupPolicy { priority: 10, ..Default::default() };
        first.sensors.insert("network".into(), false);
        let mut second = GroupPolicy { telemetry_level: Some(TelemetryLevel::Standard), priority: 1, ..Default::default() };
        second.sensors.insert("network".into(), true);
        second.sensors.insert("filesystem".into(), false);
        let r = resolve(t, &[input(1, t, first), input(2, t, second)]);
        assert_eq!(r.effective.sensors.get("network"), Some(&false));
        assert_eq!(r.effective.sensors.get("filesystem"), Some(&false));
        assert_eq!(r.effective.telemetry_level, Some(TelemetryLevel::Standard));
        assert_eq!(r.sensor_sources["network"].group_id, gid(1));
        assert_eq!(r.sensor_sources["filesystem"].group_id, gid(2));
    }

    #[test]
    fn hash_is_deterministic_and_content_sensitive() {
        let mut p = EffectivePolicy { telemetry_level: Some(TelemetryLevel::Standard), heartbeat_interval_secs: Some(30), ..Default::default() };
        p.sensors.insert("network".into(), false);
        let h1 = p.hash();
        assert_eq!(h1, p.clone().hash());
        let mut q = p.clone();
        q.sensors.insert("network".into(), true);
        assert_ne!(h1, q.hash());
        assert_eq!(p.hash_hex().len(), 64);
        assert_eq!(EffectivePolicy::default().hash_hex(), empty_policy_hash_hex());
        assert!(EffectivePolicy::default().is_empty());
        assert!(!p.is_empty());
    }

    #[test]
    fn level_serializes_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&TelemetryLevel::Detailed).unwrap(), "\"DETAILED\"");
    }
}
```

- [ ] **Step 3: Run** `cargo test -p osiris-policy` → compile FAIL.

- [ ] **Step 4: Implement `src/lib.rs`** (above the tests)

```rust
//! Group policy model for Fleet Manager policy distribution (Phase 9d-3).
//! Pure: no I/O. Shared by the server (resolution, reconciliation) and the
//! agent (validation, filtering, hashing) so both sides agree byte-for-byte.

use std::collections::BTreeMap;

use osiris_schema::EventType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const KNOWN_SENSORS: [&str; 7] = [
    "container", "filesystem", "identity", "network", "persistence", "process_exec", "systemd",
];
pub const MIN_HEARTBEAT_SECS: u64 = 10;
pub const MAX_HEARTBEAT_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryLevel {
    Minimal,
    Standard,
    Detailed,
    Forensic,
}

impl TelemetryLevel {
    pub fn code(self) -> u8 {
        match self {
            TelemetryLevel::Minimal => 1,
            TelemetryLevel::Standard => 2,
            TelemetryLevel::Detailed => 3,
            TelemetryLevel::Forensic => 4,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(TelemetryLevel::Minimal),
            2 => Some(TelemetryLevel::Standard),
            3 => Some(TelemetryLevel::Detailed),
            4 => Some(TelemetryLevel::Forensic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("unknown sensor: {0}")]
    UnknownSensor(String),
    #[error("heartbeat_interval_secs must be between 10 and 3600")]
    HeartbeatOutOfRange,
}

fn validate_fields(sensors: &BTreeMap<String, bool>, heartbeat: Option<u64>) -> Result<(), PolicyError> {
    if let Some(name) = sensors.keys().find(|n| !KNOWN_SENSORS.contains(&n.as_str())) {
        return Err(PolicyError::UnknownSensor(name.clone()));
    }
    if heartbeat.is_some_and(|h| !(MIN_HEARTBEAT_SECS..=MAX_HEARTBEAT_SECS).contains(&h)) {
        return Err(PolicyError::HeartbeatOutOfRange);
    }
    Ok(())
}

/// A policy attached to one host group. Every field is optional: "unset"
/// means the group has no opinion on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicy {
    #[serde(default)]
    pub telemetry_level: Option<TelemetryLevel>,
    #[serde(default)]
    pub sensors: BTreeMap<String, bool>,
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    pub priority: i32,
}

impl GroupPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_fields(&self.sensors, self.heartbeat_interval_secs)
    }
}

/// What one host should run: only the fields some group defined.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicy {
    #[serde(default)]
    pub telemetry_level: Option<TelemetryLevel>,
    #[serde(default)]
    pub sensors: BTreeMap<String, bool>,
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,
}

impl EffectivePolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_fields(&self.sensors, self.heartbeat_interval_secs)
    }

    pub fn is_empty(&self) -> bool {
        self.telemetry_level.is_none() && self.sensors.is_empty() && self.heartbeat_interval_secs.is_none()
    }

    pub fn hash(&self) -> [u8; 32] {
        let sensors: Vec<(&str, bool)> = self.sensors.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        let mut hasher = Sha256::new();
        hasher.update(b"osiris-policy-v1\0");
        hasher.update(encode_fields(self.telemetry_level, &sensors, self.heartbeat_interval_secs));
        hasher.finalize().into()
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }
}

/// The field encoding shared by the policy hash and the signed
/// `ApplyPolicy` command. `sensors` must already be in the order to encode.
pub fn encode_fields(level: Option<TelemetryLevel>, sensors: &[(&str, bool)], heartbeat: Option<u64>) -> Vec<u8> {
    let mut o = Vec::new();
    o.push(level.map_or(0, TelemetryLevel::code));
    o.extend_from_slice(&u32::try_from(sensors.len()).expect("sensor count fits u32").to_be_bytes());
    for (name, enabled) in sensors {
        o.extend_from_slice(&u32::try_from(name.len()).expect("name fits u32").to_be_bytes());
        o.extend_from_slice(name.as_bytes());
        o.push(u8::from(*enabled));
    }
    match heartbeat {
        None => o.push(0),
        Some(h) => {
            o.push(1);
            o.extend_from_slice(&h.to_be_bytes());
        }
    }
    o
}

/// The hash an agent without any remote policy reports (as `null`).
pub fn empty_policy_hash_hex() -> String {
    EffectivePolicy::default().hash_hex()
}

/// The lowest level at which an event type is emitted; `None` = always
/// emitted. Exhaustive on purpose: a new `EventType` must pick a level.
fn min_level(t: EventType) -> Option<TelemetryLevel> {
    use EventType::*;
    use TelemetryLevel::*;
    match t {
        AgentHealth | SensorHealth | AgentStart | AgentStop => None,
        ProcessExec | ProcessExit | PrivilegeUidChange | PrivilegeGidChange
        | PrivilegeCapabilityChange | PrivilegeSudo | PrivilegeSetuid | SessionLogin
        | SessionLogout | PersistenceCreated | PersistenceModified | PersistenceRemoved
        | ServiceCreate | ServiceModify | ServiceDelete | ModuleLoad | ModuleUnload
        | ContainerCreate | ContainerStart | ContainerStop | ContainerDestroy | LsmDenial => Some(Minimal),
        ProcessFork | SessionCreate | SessionTerminate | ServiceStart | ServiceStop | TimerCreate
        | TimerModify | NetworkConnect | NetworkAccept | NetworkClose | DnsQuery | FileCreate
        | FileDelete | FileRename | FileMove | FileExecute | FilePermissionChange
        | FileOwnerChange => Some(Standard),
        FileModify | FileWrite | FileAttributeChange | SocketCreate | SocketBind | SocketListen
        | CapabilityUse => Some(Detailed),
    }
}

pub fn allows(level: Option<TelemetryLevel>, t: EventType) -> bool {
    match (level, min_level(t)) {
        (None, _) | (_, None) => true,
        (Some(level), Some(min)) => level >= min,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyTier {
    Platform,
    Tenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSource {
    pub group_id: Uuid,
    pub tier: PolicyTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicyInput {
    pub group_id: Uuid,
    /// `None` = platform group.
    pub group_tenant: Option<Uuid>,
    pub policy: GroupPolicy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub effective: EffectivePolicy,
    pub level_source: Option<FieldSource>,
    pub sensor_sources: BTreeMap<String, FieldSource>,
    pub heartbeat_source: Option<FieldSource>,
}

/// Merges the policies of every group a host belongs to (spec §3.4).
pub fn resolve(host_tenant: Option<Uuid>, inputs: &[GroupPolicyInput]) -> ResolvedPolicy {
    let mut ordered: Vec<(PolicyTier, &GroupPolicyInput)> = inputs
        .iter()
        .filter_map(|i| match i.group_tenant {
            None => Some((PolicyTier::Platform, i)),
            Some(t) if Some(t) == host_tenant => Some((PolicyTier::Tenant, i)),
            Some(_) => None,
        })
        .collect();
    let rank = |t: PolicyTier| match t {
        PolicyTier::Platform => 0,
        PolicyTier::Tenant => 1,
    };
    ordered.sort_by(|(ta, a), (tb, b)| {
        rank(*ta)
            .cmp(&rank(*tb))
            .then(b.policy.priority.cmp(&a.policy.priority))
            .then(a.group_id.cmp(&b.group_id))
    });
    let mut out = ResolvedPolicy::default();
    for (tier, input) in ordered {
        let source = FieldSource { group_id: input.group_id, tier };
        if out.effective.telemetry_level.is_none() {
            if let Some(level) = input.policy.telemetry_level {
                out.effective.telemetry_level = Some(level);
                out.level_source = Some(source);
            }
        }
        for (name, enabled) in &input.policy.sensors {
            if !out.effective.sensors.contains_key(name) {
                out.effective.sensors.insert(name.clone(), *enabled);
                out.sensor_sources.insert(name.clone(), source);
            }
        }
        if out.effective.heartbeat_interval_secs.is_none() {
            if let Some(h) = input.policy.heartbeat_interval_secs {
                out.effective.heartbeat_interval_secs = Some(h);
                out.heartbeat_source = Some(source);
            }
        }
    }
    out
}
```

If the compiler reports `EventType` variants missing from `min_level`, the enum grew since this plan was written: place each new variant at the level its nearest sibling uses and list it in your report.

- [ ] **Step 5: Run** `cargo test -p osiris-policy` → PASS.

- [ ] **Step 6: Gates and commit**

```bash
git add crates/osiris-policy Cargo.lock
git commit -m "feat(policy): group policy model, level table, resolution and hash (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `osiris-command` — signed `ApplyPolicy` action

**Files:**
- Modify: `crates/osiris-command/Cargo.toml` (add `osiris-policy = { path = "../osiris-policy" }`)
- Modify: `crates/osiris-command/src/envelope.rs`, `src/executor.rs`, `src/runner.rs`, `src/lib.rs`
- Modify (compiler-driven): every exhaustive `match` on `CommandAction` / `FailCode` elsewhere (`guard.rs`, `crates/osiris-response/src/remote.rs`, `crates/osiris-api/src/response.rs`, `crates/osiris-server/src/control.rs`, `crates/osiris-transport/src/control.rs`, `crates/osiris-agent/src/control.rs`)

**Interfaces:**
- Consumes: Task 1 `TelemetryLevel`, `EffectivePolicy`, `encode_fields`.
- Produces: `CommandAction::ApplyPolicy { policy: PolicyPayload }`; `pub struct PolicyPayload { pub telemetry_level: Option<TelemetryLevel>, pub sensors: Vec<(String, bool)>, pub heartbeat_interval_secs: Option<u64>, pub policy_hash: [u8; 32] }` with `from_effective(&EffectivePolicy) -> Self` and `to_effective(&self) -> Result<EffectivePolicy, String>`; `FailCode::InvalidRequest`; `ActionExecutor::apply_policy(&self, &PolicyPayload, dry_run: bool) -> Result<ExecDetail, ExecFailure>` with a default body returning `Err(FailCode::Unsupported, "policy application is not supported by this executor")`; `FakeExecutor` overrides it, recording `apply_policy hash=<hex> dry_run=<bool>`. All re-exported from `osiris_command`.

- [ ] **Step 1: Failing tests** in `envelope.rs`'s test module:

```rust
    fn policy_action() -> CommandAction {
        let mut e = osiris_policy::EffectivePolicy {
            telemetry_level: Some(osiris_policy::TelemetryLevel::Standard),
            heartbeat_interval_secs: Some(30),
            ..Default::default()
        };
        e.sensors.insert("network".into(), false);
        CommandAction::ApplyPolicy { policy: PolicyPayload::from_effective(&e) }
    }

    #[test]
    fn apply_policy_canonical_bytes_are_stable() {
        let a = sample(policy_action()).canonical_bytes();
        let b = sample(policy_action()).canonical_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn changing_any_policy_field_breaks_the_signature() {
        let key = crate::keys::generate_signing_key();
        let signed = sign(sample(policy_action()), &key);
        let mutate = |f: &dyn Fn(&mut PolicyPayload)| {
            let mut s = signed.clone();
            let CommandAction::ApplyPolicy { policy } = &mut s.command.action else { unreachable!() };
            f(policy);
            verify(&s, &key.verifying_key()).is_err()
        };
        assert!(mutate(&|p| p.telemetry_level = Some(osiris_policy::TelemetryLevel::Minimal)));
        assert!(mutate(&|p| p.telemetry_level = None));
        assert!(mutate(&|p| p.sensors[0].1 = true));
        assert!(mutate(&|p| p.sensors.push(("filesystem".into(), false))));
        assert!(mutate(&|p| p.heartbeat_interval_secs = Some(31)));
        assert!(mutate(&|p| p.policy_hash[0] ^= 1));
        assert!(verify(&signed, &key.verifying_key()).is_ok());
    }

    #[test]
    fn to_effective_rejects_tampered_or_invalid_payloads() {
        let CommandAction::ApplyPolicy { policy } = policy_action() else { unreachable!() };
        assert!(policy.to_effective().is_ok());
        let mut bad_hash = policy.clone();
        bad_hash.heartbeat_interval_secs = Some(60);
        assert_eq!(bad_hash.to_effective().unwrap_err(), "policy_hash does not match policy content");
        let mut unsorted = policy.clone();
        unsorted.sensors = vec![("network".into(), false), ("filesystem".into(), true)];
        assert_eq!(unsorted.to_effective().unwrap_err(), "sensors must be sorted by name and unique");
        let mut unknown = PolicyPayload::from_effective(&Default::default());
        unknown.sensors = vec![("dns".into(), true)];
        assert_eq!(unknown.to_effective().unwrap_err(), "unknown sensor: dns");
    }
```

And in `runner.rs`'s tests:

```rust
    #[test]
    fn apply_policy_reaches_the_executor_and_default_executors_refuse_it() {
        let (_d, key, guard) = setup();
        let ex = FakeExecutor::default();
        let payload = crate::PolicyPayload::from_effective(&Default::default());
        let sc = sign(
            Command {
                command_id: Uuid::new_v4(),
                host_id: Uuid::from_u128(2),
                action: CommandAction::ApplyPolicy { policy: payload.clone() },
                dry_run: false,
                issued_at_ms: NOW,
                expires_at_ms: NOW + 30_000,
                nonce: [1; 16],
                actor: "policy-reconciler".into(),
                reason: "r".into(),
            },
            &key,
        );
        assert!(matches!(run_command(&guard, &ex, &sc, NOW), CommandResult::Executed { .. }));
        assert!(ex.calls.lock().unwrap()[0].starts_with("apply_policy hash="));

        struct NoPolicy;
        impl ActionExecutor for NoPolicy {
            fn terminate(&self, _: u32, _: &str, _: u64, _: bool) -> Result<crate::ExecDetail, crate::ExecFailure> { unreachable!() }
            fn quarantine(&self, _: &str, _: u64, _: u64, _: bool) -> Result<crate::ExecDetail, crate::ExecFailure> { unreachable!() }
            fn restore(&self, _: Uuid, _: bool) -> Result<crate::ExecDetail, crate::ExecFailure> { unreachable!() }
        }
        let err = NoPolicy.apply_policy(&payload, false).unwrap_err();
        assert_eq!(err.code, FailCode::Unsupported);
    }
```

Run `cargo test -p osiris-command` → FAIL.

- [ ] **Step 2: Implement**

`envelope.rs`:

```rust
use osiris_policy::{EffectivePolicy, TelemetryLevel};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub telemetry_level: Option<TelemetryLevel>,
    /// Sorted by name, unique.
    pub sensors: Vec<(String, bool)>,
    pub heartbeat_interval_secs: Option<u64>,
    pub policy_hash: [u8; 32],
}

impl PolicyPayload {
    pub fn from_effective(e: &EffectivePolicy) -> Self {
        Self {
            telemetry_level: e.telemetry_level,
            sensors: e.sensors.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            heartbeat_interval_secs: e.heartbeat_interval_secs,
            policy_hash: e.hash(),
        }
    }

    /// Rebuilds the policy, rejecting anything the server could not have
    /// produced: unsorted/duplicate sensors, invalid fields, or a hash that
    /// does not match the content.
    pub fn to_effective(&self) -> Result<EffectivePolicy, String> {
        if self.sensors.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err("sensors must be sorted by name and unique".into());
        }
        let e = EffectivePolicy {
            telemetry_level: self.telemetry_level,
            sensors: self.sensors.iter().cloned().collect(),
            heartbeat_interval_secs: self.heartbeat_interval_secs,
        };
        e.validate().map_err(|err| err.to_string())?;
        if e.hash() != self.policy_hash {
            return Err("policy_hash does not match policy content".into());
        }
        Ok(e)
    }
}
```

Add the variant `ApplyPolicy { policy: PolicyPayload }` to `CommandAction`, and in `canonical_bytes`:

```rust
            CommandAction::ApplyPolicy { policy } => {
                o.push(4);
                let sensors: Vec<(&str, bool)> =
                    policy.sensors.iter().map(|(k, v)| (k.as_str(), *v)).collect();
                o.extend_from_slice(&osiris_policy::encode_fields(
                    policy.telemetry_level,
                    &sensors,
                    policy.heartbeat_interval_secs,
                ));
                o.extend_from_slice(&policy.policy_hash);
            }
```

`executor.rs`: add `InvalidRequest` to `FailCode`; add to the trait:

```rust
    /// Phase 9d-3. Executors that cannot apply policy (the OS-level
    /// executors) keep this default.
    fn apply_policy(
        &self,
        _policy: &crate::envelope::PolicyPayload,
        _dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        Err(ExecFailure {
            code: FailCode::Unsupported,
            message: "policy application is not supported by this executor".into(),
        })
    }
```

and in `impl ActionExecutor for FakeExecutor`:

```rust
    fn apply_policy(
        &self,
        policy: &crate::envelope::PolicyPayload,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.respond(
            format!("apply_policy hash={} dry_run={dry_run}", hex::encode(policy.policy_hash)),
            dry_run,
        )
    }
```

`runner.rs` match arm: `CommandAction::ApplyPolicy { policy } => exec.apply_policy(policy, dry),`. `lib.rs`: re-export `PolicyPayload`.

Other exhaustive matches (the compiler lists them). Rules: `guard.rs` — `ApplyPolicy` has no pid/path target, so no protected-target check (it still passes signature/host/expiry/TTL/replay checks, which don't look at the action). Anywhere an action is rendered for humans/audit/logging, render `apply policy <first 12 hex of policy_hash>`. `osiris-response`'s event-derived resolution never produces `ApplyPolicy`; match arms that map an action to a response kind must return the existing "not a response action" / unknown branch for it. Any exhaustive `FailCode` match maps `InvalidRequest` the same way it maps `Unverifiable` (a client-side-invalid request). List every site you touched in the report.

- [ ] **Step 3: Run** `cargo test -p osiris-command` → PASS; then the gates.

- [ ] **Step 4: Commit**

```bash
git add crates Cargo.lock
git commit -m "feat(command): signed ApplyPolicy action with full-payload signature coverage (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `osiris-fleet` — hosts.db v2, `PolicyStore`, applied hash

**Files:**
- Modify: `crates/osiris-fleet/Cargo.toml` (add `osiris-policy`), `crates/osiris-fleet/src/lib.rs`
- Create: `crates/osiris-fleet/src/policies.rs`
- Modify (compiler-driven): every `HostRow { .. }` literal in the workspace (add `applied_policy_hash: None`); every exhaustive `match` on `GroupError` (map `InvalidPolicy` → 400 with its message, like `InvalidName`).

**Interfaces:**
- Consumes: Task 1 `GroupPolicy`, `GroupPolicyInput`; 9d-2 `GroupScope`, `GroupError`, `get_in_scope` (private helper in `groups.rs` — make it `pub(crate)`).
- Produces: `SCHEMA_VERSION = 2`; `HostRow.applied_policy_hash: Option<String>`; `GroupError::InvalidPolicy(String)`; `DeliveryResult { Executed, Refused, Failed, Offline, TimedOut }` (serde SCREAMING_SNAKE_CASE, `as_str()`, `parse(&str) -> Option<Self>`); `DeliveryRow { host_id: Uuid, desired_hash: String, last_sent_at: u64, last_result: DeliveryResult, last_error: Option<String> }`; trait `PolicyStore` (below) implemented by `SqliteHostRegistry`.

```rust
pub trait PolicyStore: Send + Sync {
    fn get_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<Option<GroupPolicy>, GroupError>;
    fn set_policy(&self, scope: &GroupScope, group_id: Uuid, policy: &GroupPolicy, updated_by: &str) -> Result<(), GroupError>;
    fn clear_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError>;
    /// Raw, unscoped: every policy of every group `host_id` belongs to.
    fn policies_for_host(&self, host_id: Uuid) -> Result<Vec<GroupPolicyInput>, GroupError>;
    fn all_host_policies(&self) -> Result<HashMap<Uuid, Vec<GroupPolicyInput>>, GroupError>;
    fn hosts_of_group_raw(&self, group_id: Uuid) -> Result<Vec<Uuid>, GroupError>;
    fn record_delivery(&self, row: &DeliveryRow) -> Result<(), GroupError>;
    fn delivery(&self, host_id: Uuid) -> Result<Option<DeliveryRow>, GroupError>;
    fn all_deliveries(&self) -> Result<HashMap<Uuid, DeliveryRow>, GroupError>;
}
```

- [ ] **Step 1: Failing tests** in `policies.rs` (reuse the `seed_host` pattern from `groups.rs` tests; fully qualify `get`/`list` when both traits are in scope; compare Uuid vectors against `Vec::<Uuid>::new()` when empty):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FleetError, GroupScope, HostGroupStore, HostRegistry, HostRow, SqliteHostRegistry, SCHEMA_VERSION};
    use osiris_health::HealthState;
    use osiris_policy::{GroupPolicy, TelemetryLevel};

    const P: GroupScope = GroupScope::Platform;

    fn open(dir: &tempfile::TempDir) -> SqliteHostRegistry {
        SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap()
    }

    fn row(host_id: Uuid, last_seen: u64, hash: Option<&str>) -> HostRow {
        HostRow {
            host_id,
            hostname: "h".into(),
            distro: "d".into(),
            kernel_version: "k".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: last_seen,
            last_seen,
            health_state: HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
            applied_policy_hash: hash.map(str::to_string),
        }
    }

    fn level(l: TelemetryLevel) -> GroupPolicy {
        GroupPolicy { telemetry_level: Some(l), ..Default::default() }
    }

    #[test]
    fn set_get_clear_round_trip_and_scope() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let t = Uuid::new_v4();
        let g = reg.create(&GroupScope::Tenant(t), None, "g").unwrap();
        assert_eq!(reg.get_policy(&P, g.group_id).unwrap(), None);
        reg.set_policy(&GroupScope::Tenant(t), g.group_id, &level(TelemetryLevel::Standard), "u").unwrap();
        assert_eq!(reg.get_policy(&P, g.group_id).unwrap(), Some(level(TelemetryLevel::Standard)));
        let other = GroupScope::Tenant(Uuid::new_v4());
        assert_eq!(reg.get_policy(&other, g.group_id), Err(GroupError::NotFound));
        assert_eq!(reg.set_policy(&other, g.group_id, &level(TelemetryLevel::Minimal), "u"), Err(GroupError::NotFound));
        assert_eq!(reg.clear_policy(&other, g.group_id), Err(GroupError::NotFound));
        reg.clear_policy(&GroupScope::Tenant(t), g.group_id).unwrap();
        assert_eq!(reg.get_policy(&P, g.group_id).unwrap(), None);
    }

    #[test]
    fn an_invalid_policy_is_rejected_by_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "g").unwrap();
        let mut bad = GroupPolicy::default();
        bad.sensors.insert("dns".into(), true);
        assert_eq!(reg.set_policy(&P, g.group_id, &bad, "u"), Err(GroupError::InvalidPolicy("unknown sensor: dns".into())));
    }

    #[test]
    fn policies_for_host_is_raw_and_carries_group_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 1, None)).unwrap();
        let t = Uuid::new_v4();
        let pg = reg.create(&P, None, "p").unwrap();
        let tg = reg.create(&GroupScope::Tenant(t), None, "t").unwrap();
        let bare = reg.create(&P, None, "no-policy").unwrap();
        for g in [&pg, &tg, &bare] {
            reg.add_member(&P, g.group_id, h).unwrap();
        }
        reg.set_policy(&P, pg.group_id, &level(TelemetryLevel::Minimal), "u").unwrap();
        reg.set_policy(&P, tg.group_id, &level(TelemetryLevel::Forensic), "u").unwrap();
        let mut got = reg.policies_for_host(h).unwrap();
        got.sort_by_key(|i| i.group_tenant.is_some());
        assert_eq!(got.len(), 2, "groups without a policy contribute nothing");
        assert_eq!(got[0].group_tenant, None);
        assert_eq!(got[1].group_tenant, Some(t));
        assert_eq!(reg.all_host_policies().unwrap()[&h].len(), 2);
        assert_eq!(reg.hosts_of_group_raw(pg.group_id).unwrap(), vec![h]);
    }

    #[test]
    fn deleting_a_group_deletes_its_policy() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let g = reg.create(&P, None, "g").unwrap();
        reg.set_policy(&P, g.group_id, &level(TelemetryLevel::Minimal), "u").unwrap();
        reg.delete(&P, g.group_id).unwrap();
        let n: i64 = reg.conn.lock().unwrap().query_row("SELECT COUNT(*) FROM group_policies", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn applied_hash_obeys_the_freshness_gate() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 100, Some("new"))).unwrap();
        reg.upsert_heartbeat(row(h, 50, Some("old"))).unwrap();
        assert_eq!(HostRegistry::get(&reg, h).unwrap().unwrap().applied_policy_hash.as_deref(), Some("new"));
        reg.upsert_heartbeat(row(h, 200, None)).unwrap();
        assert_eq!(HostRegistry::get(&reg, h).unwrap().unwrap().applied_policy_hash, None);
    }

    #[test]
    fn deliveries_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let reg = open(&dir);
        let h = Uuid::new_v4();
        reg.upsert_heartbeat(row(h, 1, None)).unwrap();
        let d = DeliveryRow { host_id: h, desired_hash: "abc".into(), last_sent_at: 7, last_result: DeliveryResult::Refused, last_error: Some("replay".into()) };
        reg.record_delivery(&d).unwrap();
        assert_eq!(reg.delivery(h).unwrap(), Some(d.clone()));
        let d2 = DeliveryRow { last_result: DeliveryResult::Executed, last_error: None, last_sent_at: 9, ..d };
        reg.record_delivery(&d2).unwrap();
        assert_eq!(reg.all_deliveries().unwrap()[&h], d2);
    }

    #[test]
    fn a_v1_database_migrates_to_v2_keeping_groups_and_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        let h = Uuid::new_v4();
        let gid;
        {
            // Build a genuine v1 file: v1 schema, one host, one group with a member, user_version 1.
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
            conn.execute_batch(crate::SCHEMA_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO hosts VALUES (?1,'old','d','k','0.1.0',5,5,'{\"state\":\"HEALTHY\"}',NULL,NULL,NULL)",
                [h.to_string()],
            ).unwrap();
            gid = Uuid::new_v4();
            conn.execute("INSERT INTO host_groups VALUES (?1,'g',NULL,1)", [gid.to_string()]).unwrap();
            conn.execute("INSERT INTO host_group_members VALUES (?1,?2,1)", [gid.to_string(), h.to_string()]).unwrap();
        }
        let reg = SqliteHostRegistry::open(&path).unwrap();
        assert_eq!(HostGroupStore::get(&reg, &P, gid).unwrap().member_count, 1);
        assert_eq!(HostRegistry::get(&reg, h).unwrap().unwrap().applied_policy_hash, None);
        reg.set_policy(&P, gid, &level(TelemetryLevel::Minimal), "u").unwrap();
        let v: i64 = reg.conn.lock().unwrap().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        drop(reg);
        SqliteHostRegistry::open(&path).unwrap(); // reopening a v2 file is idempotent
    }

    #[test]
    fn a_version_3_database_still_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.db");
        rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", 3).unwrap();
        assert!(matches!(SqliteHostRegistry::open(&path), Err(FleetError::UnsupportedSchema(3))));
    }
}
```

Update 9d-2's existing `a_newer_schema_version_refuses_to_open` test if it used 2 as the "newer" value (it used 99 — leave it).

Run `cargo test -p osiris-fleet` → FAIL.

- [ ] **Step 2: Implement schema v2 in `lib.rs`**

Rename today's `SCHEMA` constant to `pub(crate) const SCHEMA_V1` (unchanged content). Set `pub const SCHEMA_VERSION: i64 = 2;`. Add:

```rust
const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS group_policies (
    group_id TEXT PRIMARY KEY REFERENCES host_groups(group_id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_policy_delivery (
    host_id TEXT PRIMARY KEY REFERENCES hosts(host_id),
    desired_hash TEXT NOT NULL,
    last_sent_at INTEGER NOT NULL,
    last_result TEXT NOT NULL,
    last_error TEXT NULL
);
";
```

`open()` becomes:

```rust
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(FleetError::UnsupportedSchema(version));
        }
        conn.execute_batch(SCHEMA_V1)?;
        if version < 2 {
            // v1 -> v2 as one unit: a crash mid-way leaves user_version < 2
            // and the next open redoes it (every step is idempotent).
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA_V2)?;
            let has_column: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('hosts') WHERE name = 'applied_policy_hash'",
                [],
                |r| r.get(0),
            )?;
            if has_column == 0 {
                tx.execute("ALTER TABLE hosts ADD COLUMN applied_policy_hash TEXT NULL", [])?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
        }
```

`HostRow` gains `pub applied_policy_hash: Option<String>` (doc: lowercase hex of the agent's applied policy; `None` = no policy). `upsert_heartbeat` adds `applied_policy_hash` to the column list (`?11`), to `VALUES`, and `applied_policy_hash = excluded.applied_policy_hash` inside the gated `DO UPDATE SET`. Every `SELECT` feeding `row_from` appends `applied_policy_hash` (index 11) and `row_from` reads `applied_policy_hash: r.get(11)?`. Add `GroupError::InvalidPolicy(String)` with `#[error("{0}")]`. `mod policies; pub use policies::{DeliveryResult, DeliveryRow, PolicyStore};`.

- [ ] **Step 3: Implement `policies.rs`**

```rust
//! Group policies and per-host delivery state (Phase 9d-3), on the same
//! hosts.db connection as the registry and groups.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_policy::{GroupPolicy, GroupPolicyInput};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::groups::get_in_scope;
use crate::{to_stored_i64, GroupError, GroupScope, SqliteHostRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryResult {
    Executed,
    Refused,
    Failed,
    Offline,
    TimedOut,
}

impl DeliveryResult {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryResult::Executed => "EXECUTED",
            DeliveryResult::Refused => "REFUSED",
            DeliveryResult::Failed => "FAILED",
            DeliveryResult::Offline => "OFFLINE",
            DeliveryResult::TimedOut => "TIMED_OUT",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Executed, Self::Refused, Self::Failed, Self::Offline, Self::TimedOut]
            .into_iter()
            .find(|r| r.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryRow {
    pub host_id: Uuid,
    pub desired_hash: String,
    /// ns since the Unix epoch, server clock.
    pub last_sent_at: u64,
    pub last_result: DeliveryResult,
    pub last_error: Option<String>,
}

pub trait PolicyStore: Send + Sync { /* exactly the trait in Interfaces above */ }

fn backend(e: impl std::fmt::Display) -> GroupError {
    GroupError::Backend(e.to_string())
}

fn uuid_at(r: &rusqlite::Row, idx: usize) -> rusqlite::Result<Uuid> {
    let s: String = r.get(idx)?;
    Uuid::parse_str(&s).map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e)))
}

fn policy_input(r: &rusqlite::Row, base: usize) -> rusqlite::Result<GroupPolicyInput> {
    let tenant: Option<String> = r.get(base + 1)?;
    let json: String = r.get(base + 2)?;
    Ok(GroupPolicyInput {
        group_id: uuid_at(r, base)?,
        group_tenant: tenant
            .map(|t| Uuid::parse_str(&t))
            .transpose()
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(base + 1, rusqlite::types::Type::Text, Box::new(e)))?,
        policy: serde_json::from_str(&json)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(base + 2, rusqlite::types::Type::Text, Box::new(e)))?,
    })
}

fn delivery_from(r: &rusqlite::Row) -> rusqlite::Result<DeliveryRow> {
    let result: String = r.get(3)?;
    Ok(DeliveryRow {
        host_id: uuid_at(r, 0)?,
        desired_hash: r.get(1)?,
        last_sent_at: r.get::<_, i64>(2)? as u64,
        last_result: DeliveryResult::parse(&result).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, format!("bad delivery result {result}").into())
        })?,
        last_error: r.get(4)?,
    })
}

const HOST_POLICIES: &str = "SELECT m.host_id, p.group_id, g.tenant_id, p.policy_json
     FROM host_group_members m
     JOIN group_policies p ON p.group_id = m.group_id
     JOIN host_groups g ON g.group_id = m.group_id";

impl PolicyStore for SqliteHostRegistry {
    fn get_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<Option<GroupPolicy>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        let json: Option<String> = conn
            .query_row("SELECT policy_json FROM group_policies WHERE group_id = ?1", params![group_id.to_string()], |r| r.get(0))
            .optional()
            .map_err(backend)?;
        json.map(|j| serde_json::from_str(&j).map_err(backend)).transpose()
    }

    fn set_policy(&self, scope: &GroupScope, group_id: Uuid, policy: &GroupPolicy, updated_by: &str) -> Result<(), GroupError> {
        policy.validate().map_err(|e| GroupError::InvalidPolicy(e.to_string()))?;
        let json = serde_json::to_string(policy).map_err(backend)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute(
            "INSERT INTO group_policies (group_id, policy_json, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET policy_json = excluded.policy_json,
                 updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            params![group_id.to_string(), json, to_stored_i64(now), updated_by],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn clear_policy(&self, scope: &GroupScope, group_id: Uuid) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        get_in_scope(&conn, scope, group_id)?;
        conn.execute("DELETE FROM group_policies WHERE group_id = ?1", params![group_id.to_string()]).map_err(backend)?;
        Ok(())
    }

    fn policies_for_host(&self, host_id: Uuid) -> Result<Vec<GroupPolicyInput>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(&format!("{HOST_POLICIES} WHERE m.host_id = ?1")).map_err(backend)?;
        let rows = stmt
            .query_map(params![host_id.to_string()], |r| policy_input(r, 1))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(rows)
    }

    fn all_host_policies(&self) -> Result<HashMap<Uuid, Vec<GroupPolicyInput>>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(HOST_POLICIES).map_err(backend)?;
        let rows = stmt
            .query_map([], |r| Ok((uuid_at(r, 0)?, policy_input(r, 1)?)))
            .map_err(backend)?;
        let mut out: HashMap<Uuid, Vec<GroupPolicyInput>> = HashMap::new();
        for row in rows {
            let (host, input) = row.map_err(backend)?;
            out.entry(host).or_default().push(input);
        }
        Ok(out)
    }

    fn hosts_of_group_raw(&self, group_id: Uuid) -> Result<Vec<Uuid>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare("SELECT host_id FROM host_group_members WHERE group_id = ?1 ORDER BY host_id")
            .map_err(backend)?;
        let ids = stmt
            .query_map(params![group_id.to_string()], |r| uuid_at(r, 0))
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        Ok(ids)
    }

    fn record_delivery(&self, row: &DeliveryRow) -> Result<(), GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT INTO host_policy_delivery (host_id, desired_hash, last_sent_at, last_result, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id) DO UPDATE SET desired_hash = excluded.desired_hash,
                 last_sent_at = excluded.last_sent_at, last_result = excluded.last_result,
                 last_error = excluded.last_error",
            params![row.host_id.to_string(), row.desired_hash, to_stored_i64(row.last_sent_at), row.last_result.as_str(), row.last_error],
        )
        .map_err(backend)?;
        Ok(())
    }

    fn delivery(&self, host_id: Uuid) -> Result<Option<DeliveryRow>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT host_id, desired_hash, last_sent_at, last_result, last_error FROM host_policy_delivery WHERE host_id = ?1",
            params![host_id.to_string()],
            delivery_from,
        )
        .optional()
        .map_err(backend)
    }

    fn all_deliveries(&self) -> Result<HashMap<Uuid, DeliveryRow>, GroupError> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare("SELECT host_id, desired_hash, last_sent_at, last_result, last_error FROM host_policy_delivery")
            .map_err(backend)?;
        let rows = stmt.query_map([], delivery_from).map_err(backend)?;
        let mut out = HashMap::new();
        for row in rows {
            let d = row.map_err(backend)?;
            out.insert(d.host_id, d);
        }
        Ok(out)
    }
}
```

Add `serde_json` to `osiris-fleet`'s dependencies if absent (it is present from 9d-1).

- [ ] **Step 4: Compiler-driven updates** — add `applied_policy_hash: None` to every other `HostRow` literal (the ingest hook in `crates/osiris-server/src/ingest.rs` included — Task 7 fills it for real) and map `GroupError::InvalidPolicy(m)` to `(StatusCode::BAD_REQUEST, m)` in `crates/osiris-api/src/groups.rs`'s `group_error`.

- [ ] **Step 5: Run** `cargo test -p osiris-fleet` → PASS; gates; commit:

```bash
git add crates Cargo.lock
git commit -m "feat(fleet): hosts.db v2 with group policies, applied hash and delivery state (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Agent — policy runtime (filter, sensor manager, heartbeat interval, overlay, heartbeat hash)

**Files:**
- Create: `crates/osiris-agent/src/policy.rs`
- Modify: `crates/osiris-agent/Cargo.toml` (add `osiris-policy`), `src/lib.rs` (`pub mod policy;`), `src/agent.rs`
- Modify: `crates/osiris-sensor-api/src/raw_event.rs` (`AgentHealthRaw.policy_hash: Option<String>`), `crates/osiris-pipeline/src/normalize.rs` (`"policy_hash": raw.policy_hash` in `event_data`), and every `AgentHealthRaw { .. }` literal (compiler-driven; tests use `policy_hash: None`).

**Interfaces:**
- Consumes: Task 1 `EffectivePolicy`, `TelemetryLevel`, `allows`, `KNOWN_SENSORS`.
- Produces:
  - `osiris_agent::policy::{overlay_path(spool_path: &str) -> PathBuf, load_overlay(&Path) -> Option<EffectivePolicy>, save_overlay(&Path, &EffectivePolicy) -> std::io::Result<()>, PolicyRuntime}`.
  - `PolicyRuntime::new(base_heartbeat_secs: u64) -> (PolicyRuntime, tokio::sync::watch::Receiver<u64>)`; `allows(EventType) -> bool`; `applied() -> EffectivePolicy`; `policy_hash_hex() -> Option<String>` (None when applied is empty); `set(&EffectivePolicy)` (stores applied, level atomically, sends the effective heartbeat = policy value or base).
  - `Agent::apply_policy(&self, &EffectivePolicy) -> String` (async; returns a summary); `Agent::policy(&self) -> &Arc<PolicyRuntime>`; `Agent::overlay_path(&self) -> &Path`; `Agent::set_sensor_enabled(&self, name: &str, enabled: bool) -> SensorChange` (async) with `pub enum SensorChange { Started, Stopped, Unchanged, NotConfigured, Failed(String) }`.
  - Control is started after the `Agent` Arc exists (Task 5 passes it a `Weak<Agent>`).

- [ ] **Step 1: `policy.rs` failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_policy::TelemetryLevel;
    use osiris_schema::EventType;

    fn sample() -> EffectivePolicy {
        let mut p = EffectivePolicy { telemetry_level: Some(TelemetryLevel::Minimal), heartbeat_interval_secs: Some(30), ..Default::default() };
        p.sensors.insert("network".into(), false);
        p
    }

    #[test]
    fn overlay_round_trips_and_empty_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = overlay_path(&dir.path().join("spool.ndjson").to_string_lossy());
        assert_eq!(path.file_name().unwrap(), "spool.ndjson.policy.json");
        assert_eq!(load_overlay(&path), None);
        save_overlay(&path, &sample()).unwrap();
        assert_eq!(load_overlay(&path), Some(sample()));
        save_overlay(&path, &EffectivePolicy::default()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_or_invalid_overlay_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(load_overlay(&path), None);
        std::fs::write(&path, r#"{"sensors":{"dns":true}}"#).unwrap();
        assert_eq!(load_overlay(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_overlay_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        save_overlay(&path, &sample()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn runtime_filters_by_level_and_publishes_the_heartbeat() {
        let (rt, rx) = PolicyRuntime::new(60);
        assert!(rt.allows(EventType::FileWrite), "no policy = allow all");
        assert_eq!(*rx.borrow(), 60);
        assert_eq!(rt.policy_hash_hex(), None);
        rt.set(&sample());
        assert!(!rt.allows(EventType::FileWrite));
        assert!(rt.allows(EventType::AgentHealth));
        assert_eq!(*rx.borrow(), 30);
        assert_eq!(rt.policy_hash_hex(), Some(sample().hash_hex()));
        rt.set(&EffectivePolicy::default());
        assert_eq!(*rx.borrow(), 60, "unset heartbeat falls back to agent.yaml");
        assert_eq!(rt.policy_hash_hex(), None);
    }
}
```

- [ ] **Step 2: Implement `policy.rs`**

```rust
//! Agent-side policy state (Phase 9d-3): the persisted overlay and the live
//! knobs (level filter, heartbeat interval) the pipeline and the heartbeat
//! task read. Sensor on/off lives on `Agent` (it owns the sensors).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use osiris_policy::{allows, EffectivePolicy, TelemetryLevel};
use osiris_schema::EventType;
use tokio::sync::watch;

pub fn overlay_path(spool_path: &str) -> PathBuf {
    PathBuf::from(format!("{spool_path}.policy.json"))
}

/// `None` when absent, unreadable, unparsable or invalid — the agent then
/// runs on agent.yaml alone and reports no policy, so the server re-sends.
pub fn load_overlay(path: &Path) -> Option<EffectivePolicy> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "cannot read policy overlay; ignoring it");
            return None;
        }
    };
    let policy: EffectivePolicy = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "policy overlay is not valid JSON; ignoring it");
            return None;
        }
    };
    if let Err(e) = policy.validate() {
        tracing::error!(error = %e, path = %path.display(), "policy overlay is invalid; ignoring it");
        return None;
    }
    Some(policy)
}

/// Atomic replace (temp file, fsync, rename), private to the agent user.
/// The empty policy removes the overlay instead of writing it.
pub fn save_overlay(path: &Path, policy: &EffectivePolicy) -> std::io::Result<()> {
    if policy.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(serde_json::to_string(policy).expect("policy serializes").as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

pub struct PolicyRuntime {
    level: AtomicU8,
    base_heartbeat_secs: u64,
    heartbeat_tx: watch::Sender<u64>,
    applied: Mutex<EffectivePolicy>,
}

impl PolicyRuntime {
    pub fn new(base_heartbeat_secs: u64) -> (Self, watch::Receiver<u64>) {
        let base = base_heartbeat_secs.max(1);
        let (heartbeat_tx, rx) = watch::channel(base);
        (
            Self { level: AtomicU8::new(0), base_heartbeat_secs: base, heartbeat_tx, applied: Mutex::new(EffectivePolicy::default()) },
            rx,
        )
    }

    pub fn allows(&self, t: EventType) -> bool {
        allows(TelemetryLevel::from_code(self.level.load(Ordering::Relaxed)), t)
    }

    pub fn applied(&self) -> EffectivePolicy {
        self.applied.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn policy_hash_hex(&self) -> Option<String> {
        let applied = self.applied();
        (!applied.is_empty()).then(|| applied.hash_hex())
    }

    /// Level and heartbeat only; sensors are switched by `Agent`.
    pub fn set(&self, policy: &EffectivePolicy) {
        self.level.store(policy.telemetry_level.map_or(0, TelemetryLevel::code), Ordering::Relaxed);
        let _ = self.heartbeat_tx.send(policy.heartbeat_interval_secs.unwrap_or(self.base_heartbeat_secs));
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = policy.clone();
    }
}
```

(Add `serde_json`, `tracing`, `osiris-schema` to `osiris-agent`'s deps only if absent.)

- [ ] **Step 3: Refactor `agent.rs` — sensor factory + manager**

1. Extract a function building one sensor by name from `AgentConfig` (the 7 names in `KNOWN_SENSORS`), returning `None` when `agent.yaml` does not configure it:

```rust
fn build_sensor(config: &AgentConfig, name: &str) -> Option<Box<dyn Sensor>> {
    match name {
        "process_exec" => config.audit_log_path.clone().map(|p| Box::new(ProcessExecSensor::new(p)) as Box<dyn Sensor>),
        "filesystem" => config.fs_audit_log_path.clone().map(|p| Box::new(FilesystemSensor::new(p)) as Box<dyn Sensor>),
        "network" => config.network_proc_root.clone().map(|p| Box::new(NetworkSensor::new(p)) as Box<dyn Sensor>),
        "identity" => config.identity_audit_log_path.clone().map(|p| Box::new(IdentitySensor::new(p)) as Box<dyn Sensor>),
        "systemd" => config.systemd_audit_log_path.clone().map(|p| Box::new(SystemdSensor::new(p)) as Box<dyn Sensor>),
        "persistence" => (!config.persistence_watch_paths.is_empty())
            .then(|| Box::new(PersistenceSensor::new(config.persistence_watch_paths.clone())) as Box<dyn Sensor>),
        "container" => (!config.container_cgroup_roots.is_empty())
            .then(|| Box::new(ContainerSensor::new(config.container_cgroup_roots.clone())) as Box<dyn Sensor>),
        _ => None,
    }
}
```

Keep today's startup order for the configured sensors: iterate the same order as the current `candidate_sensors` pushes (process_exec, filesystem, network, identity, systemd, persistence, container), then the synthetic sensor (not policy-controlled).

2. Extract the capability check + initialize + start into `async fn start_sensor(sensor: Box<dyn Sensor>, raw_tx: mpsc::Sender<RawEvent>, cancellation: CancellationToken) -> Result<Box<dyn Sensor>, SkippedSensor>` (same warnings and `SkippedSensor` reasons as today).

3. `Agent` gains fields `config: AgentConfig`, `raw_tx: mpsc::Sender<RawEvent>` (a clone kept for later sensor starts), `policy: Arc<PolicyRuntime>`, `overlay_path: PathBuf`.

4. In `start`, before constructing sensors: `let overlay_path = policy::overlay_path(&config.spool_path); let (policy_rt, heartbeat_rx) = PolicyRuntime::new(config.fleet.health_interval_secs); let overlay = policy::load_overlay(&overlay_path).unwrap_or_default(); policy_rt.set(&overlay);`. A configured sensor whose name maps to `false` in `overlay.sensors` is not started; record it as `SkippedSensor { name, reason: "disabled by policy".into() }`.

5. Pipeline task: capture `let pipeline_policy = policy_rt.clone()` (Arc) and a counter `let dropped = metrics.counter("events_dropped_by_policy");`; replace `pipeline_bus.enqueue(prioritized);` with:

```rust
                                if pipeline_policy.allows(prioritized.event.event_type) {
                                    pipeline_bus.enqueue(prioritized);
                                } else {
                                    dropped.increment();
                                }
```

6. Heartbeat task: read the interval from `heartbeat_rx` and put the hash in the raw event:

```rust
            let mut heartbeat_rx = heartbeat_rx;
            let health_agent = agent.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let secs = (*heartbeat_rx.borrow()).max(1);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                        Ok(()) = heartbeat_rx.changed() => continue,
                        _ = health_cancellation.cancelled() => break,
                    }
                    // ... existing status_snapshot + aggregator code ...
                    let raw = osiris_sensor_api::RawEvent::AgentHealth(osiris_sensor_api::AgentHealthRaw {
                        agent_version: env!("CARGO_PKG_VERSION").to_string(),
                        health: aggregator.aggregate(),
                        timestamp_ns: /* unchanged */,
                        policy_hash: health_agent.policy.policy_hash_hex(),
                    });
                    // ... unchanged send ...
                }
            });
```

7. Move the `if let Some(control) = &config.control { ... start_control(...) }` block to after the `agent` Arc is created and push its handle into `agent.background_tasks` (Task 5 changes `start_control`'s signature; in this task keep calling it as today, just later).

8. Methods:

```rust
    pub fn policy(&self) -> &Arc<PolicyRuntime> {
        &self.policy
    }

    pub fn overlay_path(&self) -> &std::path::Path {
        &self.overlay_path
    }

    pub async fn set_sensor_enabled(&self, name: &str, enabled: bool) -> SensorChange {
        let mut sensors = self.sensors.lock().await;
        let position = sensors.iter().position(|s| s.name() == name);
        match (enabled, position) {
            (false, Some(i)) => {
                let mut sensor = sensors.remove(i);
                drop(sensors);
                let _ = sensor.stop().await;
                self.mark_disabled(name, true);
                SensorChange::Stopped
            }
            (false, None) => {
                if build_sensor(&self.config, name).is_some() {
                    self.mark_disabled(name, true);
                }
                SensorChange::Unchanged
            }
            (true, Some(_)) => SensorChange::Unchanged,
            (true, None) => {
                drop(sensors);
                self.mark_disabled(name, false);
                let Some(sensor) = build_sensor(&self.config, name) else {
                    return SensorChange::NotConfigured;
                };
                match start_sensor(sensor, self.raw_tx.clone(), self.cancellation.clone()).await {
                    Ok(sensor) => {
                        self.sensors.lock().await.push(sensor);
                        SensorChange::Started
                    }
                    Err(skipped) => {
                        let reason = skipped.reason.clone();
                        lock(&self.skipped_sensors).push(skipped);
                        SensorChange::Failed(reason)
                    }
                }
            }
        }
    }

    /// Keeps exactly one "disabled by policy" entry per disabled sensor.
    fn mark_disabled(&self, name: &str, disabled: bool) {
        let mut skipped = lock(&self.skipped_sensors);
        skipped.retain(|s| !(s.name == name && s.reason == "disabled by policy"));
        if disabled {
            skipped.push(SkippedSensor { name: name.to_string(), reason: "disabled by policy".into() });
        }
    }

    /// Applies an already-validated (and, by the caller, persisted) policy
    /// live. Sensors the policy leaves unset follow agent.yaml (enabled).
    pub async fn apply_policy(&self, policy: &EffectivePolicy) -> String {
        self.policy.set(policy);
        let mut notes = vec![format!(
            "level {}",
            policy.telemetry_level.map_or("unset".to_string(), |l| format!("{l:?}").to_uppercase())
        )];
        for name in osiris_policy::KNOWN_SENSORS {
            let enabled = policy.sensors.get(name).copied().unwrap_or(true);
            match self.set_sensor_enabled(name, enabled).await {
                SensorChange::Started => notes.push(format!("{name} on")),
                SensorChange::Stopped => notes.push(format!("{name} off")),
                SensorChange::Failed(r) => notes.push(format!("{name} failed: {r}")),
                SensorChange::Unchanged | SensorChange::NotConfigured => {}
            }
        }
        if let Some(h) = policy.heartbeat_interval_secs {
            notes.push(format!("heartbeat {h}s"));
        }
        notes.join("; ")
    }
```

`shutdown()` is unchanged (it still stops whatever is in `self.sensors`, and still drops the lock before awaiting background tasks).

- [ ] **Step 4: Agent tests** (in `agent.rs`'s test module; reuse `base_config` and `test_host`):

```rust
    #[tokio::test]
    async fn minimal_level_drops_file_writes_but_keeps_agent_health() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("web_shell_drop".to_string()); // emits FILE_WRITE-class events
        config.fleet.health_interval_secs = 1;
        let overlay = crate::policy::overlay_path(&config.spool_path);
        crate::policy::save_overlay(&overlay, &EffectivePolicy { telemetry_level: Some(osiris_policy::TelemetryLevel::Minimal), ..Default::default() }).unwrap();
        let agent = Agent::start(config, test_host(), "boot-1".to_string()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        agent.shutdown().await;
        let spooled = std::fs::read_to_string(&spool).unwrap();
        assert!(spooled.contains("\"event_type\":\"AGENT_HEALTH\""));
        assert!(!spooled.contains("\"event_type\":\"FILE_WRITE\""), "{spooled}");
        assert!(spooled.contains("\"policy_hash\":\""), "the heartbeat reports the applied hash");
    }

    #[tokio::test]
    async fn without_an_overlay_the_heartbeat_reports_a_null_policy_hash() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.fleet.health_interval_secs = 1;
        let agent = Agent::start(config, test_host(), "boot-1".to_string()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        agent.shutdown().await;
        assert!(std::fs::read_to_string(&spool).unwrap().contains("\"policy_hash\":null"));
    }

    #[tokio::test]
    async fn a_policy_stops_and_restarts_a_real_sensor() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::write(proc_root.join("net/tcp"), "  sl  local_address rem_address   st\n").unwrap();
        config.network_proc_root = Some(proc_root.to_string_lossy().to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string()).await.unwrap();
        let names = |s: &crate::status::AgentStatus| s.sensors.iter().map(|h| h.sensor_name.clone()).collect::<Vec<_>>();
        assert!(names(&agent.status_snapshot().await).contains(&"network".to_string()));

        let mut off = EffectivePolicy::default();
        off.sensors.insert("network".into(), false);
        let summary = agent.apply_policy(&off).await;
        assert!(summary.contains("network off"), "{summary}");
        let status = agent.status_snapshot().await;
        assert!(!names(&status).contains(&"network".to_string()));
        assert!(status.skipped_sensors.iter().any(|s| s.name == "network" && s.reason == "disabled by policy"));

        let summary = agent.apply_policy(&EffectivePolicy::default()).await;
        assert!(summary.contains("network on"), "{summary}");
        let status = agent.status_snapshot().await;
        assert!(names(&status).contains(&"network".to_string()));
        assert!(!status.skipped_sensors.iter().any(|s| s.reason == "disabled by policy"));
        agent.shutdown().await;
    }
```

Adjust only mechanical details to the real code (e.g. the field name on `SensorHealth` for the sensor's name — read `osiris-sensor-api`; the minimal valid `/proc/net/tcp` header the network sensor's `capabilities()` accepts — reuse the fixture from the existing `starts_the_network_sensor_when_a_proc_root_with_net_tcp_exists` test; pick the synthetic scenario that the existing generator tests show emits `FILE_WRITE`). Do not weaken the assertions.

Also add in `crates/osiris-pipeline/src/normalize.rs`'s tests: an `AgentHealthRaw` with `policy_hash: Some("ab".repeat(32))` normalizes to `event_data["policy_hash"] == "abab…"`, and `None` to `null`.

- [ ] **Step 5: Run** `cargo test -p osiris-agent -p osiris-pipeline -p osiris-sensor-api` → PASS; gates; commit:

```bash
git add crates Cargo.lock
git commit -m "feat(agent): live policy runtime — level filter, sensor manager, heartbeat interval, overlay (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Agent — `ApplyPolicy` executor

**Files:**
- Create: `crates/osiris-agent/src/policy_exec.rs`
- Modify: `crates/osiris-agent/src/control.rs` (`start_control` takes `agent: std::sync::Weak<crate::agent::Agent>` and wraps its executor), `src/agent.rs` (pass `Arc::downgrade(&agent)`), `src/lib.rs`
- Test: `crates/osiris-agent/src/policy_exec.rs`

**Interfaces:**
- Consumes: Task 2 `PolicyPayload::to_effective`, `ActionExecutor`, `ExecDetail`, `ExecFailure`, `FailCode::{InvalidRequest, Io}`; Task 4 `Agent::{apply_policy, policy, overlay_path}`, `save_overlay`.
- Produces: `pub struct PolicyAwareExecutor { inner: Arc<dyn ActionExecutor>, agent: Weak<Agent>, runtime: tokio::runtime::Handle }` with `new(inner, agent, runtime)`; `pub fn describe_diff(current: &EffectivePolicy, next: &EffectivePolicy) -> String`.

Order inside `apply_policy` (spec §6.1): validate (`to_effective`, else `InvalidRequest`) → agent alive (else `Io`, "agent is shutting down") → if `dry_run`: `Ok(summary "would apply: <diff>")` → persist overlay (`save_overlay`, failure → `Io` "cannot persist policy: <err>", nothing applied) → `runtime.block_on(agent.apply_policy(&effective))` → `Ok(ExecDetail { summary, quarantine_id: None, sha256: None, signal: None })`. The call runs inside the handler's `spawn_blocking`, so `Handle::block_on` is allowed there.

- [ ] **Step 1: Failing tests** (in `policy_exec.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{FailCode, FakeExecutor, PolicyPayload};
    use osiris_policy::{EffectivePolicy, TelemetryLevel};

    async fn agent_in(dir: &tempfile::TempDir) -> Arc<Agent> {
        let config = crate::agent::tests::base_config(dir);
        Agent::start(config, crate::agent::tests::test_host(), "boot".into()).await.unwrap()
    }

    fn minimal() -> EffectivePolicy {
        EffectivePolicy { telemetry_level: Some(TelemetryLevel::Minimal), heartbeat_interval_secs: Some(20), ..Default::default() }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn apply_persists_then_applies_live() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = PolicyAwareExecutor::new(Arc::new(FakeExecutor::default()), Arc::downgrade(&agent), tokio::runtime::Handle::current());
        let payload = PolicyPayload::from_effective(&minimal());
        let detail = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, false)).await.unwrap().unwrap();
        assert!(detail.summary.contains("level MINIMAL"), "{}", detail.summary);
        assert_eq!(crate::policy::load_overlay(agent.overlay_path()), Some(minimal()));
        assert_eq!(agent.policy().applied(), minimal());
        agent.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dry_run_describes_the_diff_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = PolicyAwareExecutor::new(Arc::new(FakeExecutor::default()), Arc::downgrade(&agent), tokio::runtime::Handle::current());
        let payload = PolicyPayload::from_effective(&minimal());
        let detail = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, true)).await.unwrap().unwrap();
        assert!(detail.summary.starts_with("would apply: "), "{}", detail.summary);
        assert!(detail.summary.contains("level unset -> MINIMAL"), "{}", detail.summary);
        assert_eq!(crate::policy::load_overlay(agent.overlay_path()), None);
        assert!(agent.policy().applied().is_empty());
        agent.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_payload_whose_hash_does_not_match_is_refused_without_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = PolicyAwareExecutor::new(Arc::new(FakeExecutor::default()), Arc::downgrade(&agent), tokio::runtime::Handle::current());
        let mut payload = PolicyPayload::from_effective(&minimal());
        payload.telemetry_level = Some(TelemetryLevel::Forensic);
        let err = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, false)).await.unwrap().unwrap_err();
        assert_eq!(err.code, FailCode::InvalidRequest);
        assert_eq!(crate::policy::load_overlay(agent.overlay_path()), None);
        assert!(agent.policy().applied().is_empty());
        agent.shutdown().await;
    }

    #[test]
    fn other_actions_are_delegated() {
        let inner = Arc::new(FakeExecutor::default());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let exec = PolicyAwareExecutor::new(inner.clone(), std::sync::Weak::new(), rt.handle().clone());
        exec.terminate(42, "/bin/x", 5, true).unwrap();
        assert_eq!(inner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn describe_diff_lists_each_change() {
        let mut next = minimal();
        next.sensors.insert("network".into(), false);
        let d = describe_diff(&EffectivePolicy::default(), &next);
        assert!(d.contains("level unset -> MINIMAL"));
        assert!(d.contains("network unset -> off"));
        assert!(d.contains("heartbeat unset -> 20s"));
        assert_eq!(describe_diff(&next, &next), "no change");
    }
}
```

- [ ] **Step 2: Implement `policy_exec.rs`**

```rust
//! Phase 9d-3: the agent's executor for `ApplyPolicy`. Wraps the OS-level
//! executor (terminate/quarantine/restore are delegated unchanged) so the
//! Linux-only executor needs no policy code.

use std::sync::{Arc, Weak};

use osiris_command::{ActionExecutor, ExecDetail, ExecFailure, FailCode, PolicyPayload};
use osiris_policy::EffectivePolicy;
use uuid::Uuid;

use crate::agent::Agent;

pub struct PolicyAwareExecutor {
    inner: Arc<dyn ActionExecutor>,
    agent: Weak<Agent>,
    runtime: tokio::runtime::Handle,
}

impl PolicyAwareExecutor {
    pub fn new(inner: Arc<dyn ActionExecutor>, agent: Weak<Agent>, runtime: tokio::runtime::Handle) -> Self {
        Self { inner, agent, runtime }
    }
}

fn level_str(p: &EffectivePolicy) -> String {
    p.telemetry_level.map_or("unset".into(), |l| format!("{l:?}").to_uppercase())
}

pub fn describe_diff(current: &EffectivePolicy, next: &EffectivePolicy) -> String {
    let mut parts = Vec::new();
    if current.telemetry_level != next.telemetry_level {
        parts.push(format!("level {} -> {}", level_str(current), level_str(next)));
    }
    let show = |v: Option<&bool>| v.map_or("unset", |e| if *e { "on" } else { "off" });
    for name in osiris_policy::KNOWN_SENSORS {
        let (a, b) = (current.sensors.get(name), next.sensors.get(name));
        if a != b {
            parts.push(format!("{name} {} -> {}", show(a), show(b)));
        }
    }
    if current.heartbeat_interval_secs != next.heartbeat_interval_secs {
        let show = |v: Option<u64>| v.map_or("unset".to_string(), |s| format!("{s}s"));
        parts.push(format!("heartbeat {} -> {}", show(current.heartbeat_interval_secs), show(next.heartbeat_interval_secs)));
    }
    if parts.is_empty() { "no change".into() } else { parts.join("; ") }
}

fn fail(code: FailCode, message: impl Into<String>) -> ExecFailure {
    ExecFailure { code, message: message.into() }
}

impl ActionExecutor for PolicyAwareExecutor {
    fn terminate(&self, pid: u32, exe_path: &str, observed_at_ns: u64, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.inner.terminate(pid, exe_path, observed_at_ns, dry_run)
    }

    fn quarantine(&self, path: &str, inode: u64, device_id: u64, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.inner.quarantine(path, inode, device_id, dry_run)
    }

    fn restore(&self, id: Uuid, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.inner.restore(id, dry_run)
    }

    fn apply_policy(&self, payload: &PolicyPayload, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        let next = payload.to_effective().map_err(|m| fail(FailCode::InvalidRequest, m))?;
        let agent = self.agent.upgrade().ok_or_else(|| fail(FailCode::Io, "agent is shutting down"))?;
        let detail = |summary: String| ExecDetail { summary, quarantine_id: None, sha256: None, signal: None };
        if dry_run {
            return Ok(detail(format!("would apply: {}", describe_diff(&agent.policy().applied(), &next))));
        }
        crate::policy::save_overlay(agent.overlay_path(), &next)
            .map_err(|e| fail(FailCode::Io, format!("cannot persist policy: {e}")))?;
        let summary = self.runtime.block_on(agent.apply_policy(&next));
        Ok(detail(summary))
    }
}
```

The tests reuse `agent.rs`'s `base_config`/`test_host`: change that test module's declaration to `#[cfg(test)] pub(crate) mod tests` and those two helpers to `pub(crate) fn`.

- [ ] **Step 3: Wire it**

`start_control(control, host_id, spool_path, agent: Weak<Agent>, cancel)`: wrap the executor: `Arc::new(crate::policy_exec::PolicyAwareExecutor::new(default_executor(vault, protected), agent, tokio::runtime::Handle::current()))`. `Agent::start` passes `Arc::downgrade(&agent)`. The existing `control.rs` test calling `start_control` passes `std::sync::Weak::new()`.

- [ ] **Step 4: Run** `cargo test -p osiris-agent` → PASS; gates; commit:

```bash
git add crates
git commit -m "feat(agent): ApplyPolicy executor — validate, persist, apply live (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: API — policy routes, host effective view, status on /hosts, notifier

**Files:**
- Create: `crates/osiris-api/src/policy.rs`
- Modify: `crates/osiris-api/Cargo.toml` (add `osiris-policy`), `src/lib.rs` (module + re-exports), `src/fleet.rs` (`FleetState` + `HostSummary.policy_status`), `src/groups.rs` (`GroupsState.notifier`; notify on member add/remove and before group delete), `src/auth_middleware.rs` (allowlist + tests), `crates/osiris-server/src/main.rs` (merge router; `NoopPolicyNotifier` until Task 7), both composed-router test files, `crates/osiris-e2e-tests/tests/end_to_end.rs` (new state fields).

**Interfaces:**
- Consumes: Task 1 `resolve`, `GroupPolicy`, `PolicyTier`, `empty_policy_hash_hex`; Task 3 `PolicyStore`, `DeliveryRow`, `DeliveryResult`; 9d-2 `HostGroupStore`, `GroupScope`, `crate::groups::internal`, `tenant_scope::hosts_of_tenant`.
- Produces:
  - `pub trait PolicyNotifier: Send + Sync { fn hosts_changed(&self, hosts: Vec<Uuid>); fn managed(&self) -> bool; }` and `pub struct NoopPolicyNotifier;` (`managed() == false`).
  - `#[derive(Clone)] pub struct PolicyState { pub groups: Arc<dyn HostGroupStore>, pub policies: Arc<dyn PolicyStore>, pub registry: Arc<dyn HostRegistry>, pub tenants: Arc<dyn TenantStore>, pub audit_log: Arc<dyn AuditLog + Send + Sync>, pub notifier: Arc<dyn PolicyNotifier> }`; `pub fn build_policy_router(PolicyState) -> Router`.
  - `pub(crate) fn policy_status(managed: bool, desired: &str, applied: Option<&str>, delivery: Option<&DeliveryRow>) -> &'static str`.
  - `FleetState` gains `policies: Arc<dyn PolicyStore>`, `notifier: Arc<dyn PolicyNotifier>`; `GroupsState` gains `notifier: Arc<dyn PolicyNotifier>`.

Ruling carried from the plan (spec gap): deleting a group that has a policy changes its members' effective policy, so `delete_group` fetches the group's raw members before deleting and notifies them afterwards.

- [ ] **Step 1: Failing unit tests** (in `policy.rs`; handlers called directly, following `groups.rs` test fixtures: one `Arc<SqliteHostRegistry>` shared as groups/policies/registry, a `SqliteTenantStore`, a `FileAuditLog`, and a recording notifier):

Handler signatures (the tests call them directly): `get_group_policy(Extension<AuthContext>, State<PolicyState>, Path<Uuid>) -> Result<Json<serde_json::Value>, ApiError>`, `put_group_policy(Extension, State, Path<Uuid>, Json<GroupPolicy>) -> Result<Json<serde_json::Value>, ApiError>`, `delete_group_policy(Extension, State, Path<Uuid>) -> Result<StatusCode, ApiError>`, `get_host_policy(Extension, State, Path<Uuid>) -> Result<Json<serde_json::Value>, ApiError>`.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_fleet::{GroupScope, HostRow, SqliteHostRegistry};
    use serde_json::json;

    struct Recorder(std::sync::Mutex<Vec<Uuid>>, bool);
    impl PolicyNotifier for Recorder {
        fn hosts_changed(&self, hosts: Vec<Uuid>) {
            self.0.lock().unwrap().extend(hosts);
        }
        fn managed(&self) -> bool {
            self.1
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        state: PolicyState,
        notes: Arc<Recorder>,
    }

    fn fx(managed: bool) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let notes = Arc::new(Recorder(Default::default(), managed));
        let state = PolicyState {
            groups: db.clone(),
            policies: db.clone(),
            registry: db,
            tenants: Arc::new(osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap()),
            audit_log: Arc::new(osiris_audit::FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap()),
            notifier: notes.clone(),
        };
        Fx { _dir: dir, state, notes }
    }

    fn heartbeat(state: &PolicyState, host_id: Uuid, last_seen: u64, applied: Option<String>) {
        state
            .registry
            .upsert_heartbeat(HostRow {
                host_id,
                hostname: "h".into(),
                distro: "d".into(),
                kernel_version: "k".into(),
                agent_version: "0.1.0".into(),
                enrolled_at: last_seen,
                last_seen,
                health_state: osiris_health::HealthState::Healthy,
                cloud_provider: None,
                cloud_instance_id: None,
                cloud_region: None,
                applied_policy_hash: applied,
            })
            .unwrap();
    }

    fn host(state: &PolicyState) -> Uuid {
        let h = Uuid::new_v4();
        heartbeat(state, h, crate::fleet::now_ns(), None);
        h
    }

    fn ctx(tenant_id: Option<Uuid>) -> AuthContext {
        AuthContext { user_id: Uuid::now_v7(), role: osiris_auth::Role::Admin, token: "t".into(), tenant_id }
    }

    fn body(v: serde_json::Value) -> Json<GroupPolicy> {
        Json(serde_json::from_value(v).unwrap())
    }

    async fn put(f: &Fx, c: &AuthContext, g: Uuid, v: serde_json::Value) -> Result<Json<serde_json::Value>, ApiError> {
        put_group_policy(Extension(c.clone()), State(f.state.clone()), Path(g), body(v)).await
    }

    async fn view(f: &Fx, c: &AuthContext, h: Uuid) -> Result<Json<serde_json::Value>, ApiError> {
        get_host_policy(Extension(c.clone()), State(f.state.clone()), Path(h)).await
    }

    #[tokio::test]
    async fn put_get_delete_policy_with_audit_and_notification() {
        let f = fx(true);
        let admin = ctx(None);
        let h = host(&f.state);
        let g = f.state.groups.create(&GroupScope::Platform, None, "g").unwrap();
        f.state.groups.add_member(&GroupScope::Platform, g.group_id, h).unwrap();
        let Json(v) = put(&f, &admin, g.group_id, json!({"telemetry_level": "MINIMAL"})).await.unwrap();
        assert_eq!(v["policy"]["telemetry_level"], "MINIMAL");
        let Json(v) = get_group_policy(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        assert_eq!(v["policy"]["telemetry_level"], "MINIMAL");
        assert_eq!(*f.notes.0.lock().unwrap(), vec![h]);
        assert_eq!(
            delete_group_policy(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap(),
            StatusCode::NO_CONTENT
        );
        let Json(v) = get_group_policy(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        assert!(v["policy"].is_null());
        assert_eq!(*f.notes.0.lock().unwrap(), vec![h, h]);
        let whats: Vec<String> = f.state.audit_log.read_all().unwrap().into_iter().map(|e| e.what).collect();
        assert_eq!(whats, vec!["group_policy_set", "group_policy_clear"]);
    }

    #[tokio::test]
    async fn invalid_policies_are_400_with_the_validation_message() {
        let f = fx(true);
        let g = f.state.groups.create(&GroupScope::Platform, None, "g").unwrap();
        assert_eq!(
            put(&f, &ctx(None), g.group_id, json!({"sensors": {"dns": true}})).await.unwrap_err(),
            (StatusCode::BAD_REQUEST, "unknown sensor: dns".to_string())
        );
        assert_eq!(
            put(&f, &ctx(None), g.group_id, json!({"heartbeat_interval_secs": 5})).await.unwrap_err(),
            (StatusCode::BAD_REQUEST, "heartbeat_interval_secs must be between 10 and 3600".to_string())
        );
        assert!(f.state.audit_log.read_all().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_tenant_policy_never_applies_to_another_tenants_host() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let g = f.state.groups.create(&GroupScope::Tenant(a), None, "g").unwrap();
        f.state.groups.add_member(&GroupScope::Tenant(a), g.group_id, h).unwrap();
        put(&f, &ctx(Some(a)), g.group_id, json!({"telemetry_level": "FORENSIC"})).await.unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["effective"]["telemetry_level"], "FORENSIC");
        f.state.tenants.assign_host(h, b).unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert!(v["effective"]["telemetry_level"].is_null());
    }

    #[tokio::test]
    async fn tenants_see_platform_sources_as_opaque_and_their_own_by_name() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let p = f.state.groups.create(&GroupScope::Platform, None, "P").unwrap();
        f.state.groups.add_member(&GroupScope::Platform, p.group_id, h).unwrap();
        put(&f, &ctx(None), p.group_id, json!({"telemetry_level": "MINIMAL"})).await.unwrap();
        let web = f.state.groups.create(&GroupScope::Tenant(a), None, "web").unwrap();
        f.state.groups.add_member(&GroupScope::Tenant(a), web.group_id, h).unwrap();
        put(&f, &ctx(Some(a)), web.group_id, json!({"heartbeat_interval_secs": 30})).await.unwrap();

        let Json(v) = view(&f, &ctx(Some(a)), h).await.unwrap();
        assert_eq!(v["sources"]["telemetry_level"], json!({"tier": "PLATFORM"}));
        assert_eq!(v["sources"]["heartbeat_interval_secs"]["tier"], "TENANT");
        assert_eq!(v["sources"]["heartbeat_interval_secs"]["group_name"], "web");
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["sources"]["telemetry_level"]["group_name"], "P");
        assert_eq!(v["sources"]["telemetry_level"]["group_id"], p.group_id.to_string());
    }

    #[tokio::test]
    async fn host_policy_view_scoping_and_status() {
        let f = fx(false);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let h = host(&f.state);
        f.state.tenants.assign_host(h, a).unwrap();
        let not_found = (StatusCode::NOT_FOUND, "host not found".to_string());
        assert_eq!(view(&f, &ctx(Some(b)), h).await.unwrap_err(), not_found);
        assert_eq!(view(&f, &ctx(None), Uuid::new_v4()).await.unwrap_err(), not_found);
        assert_eq!(view(&f, &ctx(None), h).await.unwrap().0["status"], "UNMANAGED");

        let f = fx(true);
        let h = host(&f.state);
        let g = f.state.groups.create(&GroupScope::Platform, None, "g").unwrap();
        f.state.groups.add_member(&GroupScope::Platform, g.group_id, h).unwrap();
        put(&f, &ctx(None), g.group_id, json!({"telemetry_level": "MINIMAL"})).await.unwrap();
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["status"], "PENDING");
        let desired = v["desired_hash"].as_str().unwrap().to_string();
        heartbeat(&f.state, h, crate::fleet::now_ns() + 1, Some(desired.clone()));
        let Json(v) = view(&f, &ctx(None), h).await.unwrap();
        assert_eq!(v["status"], "IN_SYNC");
        assert_eq!(v["applied_hash"], desired);
    }

    #[tokio::test]
    async fn a_policy_on_another_tenants_group_is_404() {
        let f = fx(true);
        let a = f.state.tenants.create_tenant("a").unwrap().tenant_id;
        let b = f.state.tenants.create_tenant("b").unwrap().tenant_id;
        let g = f.state.groups.create(&GroupScope::Tenant(a), None, "g").unwrap();
        let nf = (StatusCode::NOT_FOUND, "group not found".to_string());
        let tb = ctx(Some(b));
        assert_eq!(get_group_policy(Extension(tb.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap_err(), nf);
        assert_eq!(put(&f, &tb, g.group_id, json!({"telemetry_level": "MINIMAL"})).await.unwrap_err(), nf);
        assert_eq!(delete_group_policy(Extension(tb), State(f.state.clone()), Path(g.group_id)).await.unwrap_err(), nf);
    }

    #[test]
    fn status_rules() {
        let empty = osiris_policy::empty_policy_hash_hex();
        let d = |hash: &str, r| DeliveryRow { host_id: Uuid::nil(), desired_hash: hash.into(), last_sent_at: 0, last_result: r, last_error: None };
        assert_eq!(policy_status(false, "x", None, None), "UNMANAGED");
        assert_eq!(policy_status(true, &empty, None, None), "IN_SYNC");
        assert_eq!(policy_status(true, "x", Some("x"), None), "IN_SYNC");
        assert_eq!(policy_status(true, "x", None, None), "PENDING");
        assert_eq!(policy_status(true, "x", None, Some(&d("x", DeliveryResult::Refused))), "FAILED");
        assert_eq!(policy_status(true, "x", None, Some(&d("old", DeliveryResult::Failed))), "PENDING");
        assert_eq!(policy_status(true, "x", None, Some(&d("x", DeliveryResult::Offline))), "PENDING");
    }
}
```

Also add to `groups.rs` tests — define a `Recorder` there identical to `policy.rs`'s, build the fixture's `GroupsState` with `notifier: recorder.clone()`, and keep it in a new `Fx.recorder` field:

```rust
    #[tokio::test]
    async fn member_add_remove_and_group_delete_notify_the_affected_hosts() {
        let f = fx(); // GroupsState now built with notifier: recorder.clone()
        let admin = ctx(None);
        let h = host(&f.state, "h");
        let g = create(&f.state, &admin, "g", None).await.unwrap();
        add_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        remove_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        add_member(Extension(admin.clone()), State(f.state.clone()), Path((g.group_id, h))).await.unwrap();
        delete_group(Extension(admin.clone()), State(f.state.clone()), Path(g.group_id)).await.unwrap();
        assert_eq!(*f.recorder.0.lock().unwrap(), vec![h, h, h, h]);
    }
```

- [ ] **Step 2: Implement `policy.rs`**

Router:

```rust
pub fn build_policy_router(state: PolicyState) -> Router {
    Router::new()
        .route(
            "/api/v1/groups/:group_id/policy",
            get(get_group_policy).put(put_group_policy).delete(delete_group_policy),
        )
        .route("/api/v1/hosts/:host_id/policy", get(get_host_policy))
        .with_state(state)
}
```

Shared helpers (reuse `crate::groups::{internal, scope_of}` — make `scope_of` `pub(crate)`; map `GroupError` with the existing `group_error` made `pub(crate)` — it already maps NotFound→404, InvalidPolicy→400 after Task 3):

```rust
pub(crate) fn policy_status(managed: bool, desired: &str, applied: Option<&str>, delivery: Option<&DeliveryRow>) -> &'static str {
    if !managed {
        return "UNMANAGED";
    }
    let empty = osiris_policy::empty_policy_hash_hex();
    if applied.unwrap_or(&empty) == desired {
        return "IN_SYNC";
    }
    match delivery {
        Some(d) if d.desired_hash == desired && matches!(d.last_result, DeliveryResult::Refused | DeliveryResult::Failed) => "FAILED",
        _ => "PENDING",
    }
}
```

Handlers (all store calls through `spawn_blocking`, errors via `internal`/`group_error`):
- `get_group_policy`: `policies.get_policy(&scope, gid)` → `Json(json!({"policy": policy}))`.
- `put_group_policy(Json<GroupPolicy>)`: `policy.validate()` → 400 with the message; `set_policy(&scope, gid, &policy, &ctx.user_id.to_string())`; audit `group_policy_set` target `group:<gid>`, `why: Some(serde_json::to_string(&policy))` (the tenants.rs `audit` helper takes no `why` — write a local `audit_with_why`); `notifier.hosts_changed(policies.hosts_of_group_raw(gid))`; return `Json(json!({"policy": policy}))`.
- `delete_group_policy`: `clear_policy`; audit `group_policy_clear`; notify members; `StatusCode::NO_CONTENT`.
- `get_host_policy(Path<Uuid>)`:
  1. visibility: `hosts_of_tenant(ctx.tenant_id, Some(tenants))` → if `Some(set)` and `!set.contains(&h)` → `(404, "host not found")`; `registry.get(h)` → `None` → 404 same body.
  2. `host_tenant = tenants.tenant_of(h)`; `inputs = policies.policies_for_host(h)`; `resolved = osiris_policy::resolve(host_tenant, &inputs)`.
  3. `desired = resolved.effective.hash_hex()`; `applied = row.applied_policy_hash`; `delivery = policies.delivery(h)`.
  4. Source JSON per `FieldSource`: platform tier + tenant caller → `json!({"tier": "PLATFORM"})`; otherwise `json!({"tier": tier, "group_id": id, "group_name": name})` where `name` = `groups.get(&GroupScope::Platform, id)` (internal lookup; fall back to `null` if the group vanished).
  5. Response exactly as spec §4.2 (`effective` serialized from `EffectivePolicy`; `last_delivery` = `{sent_at, result, error}` or `null`; `status` = `policy_status(notifier.managed(), &desired, applied.as_deref(), delivery.as_ref())`).

`fleet.rs` `/hosts`: after building rows, compute bulk: `all = policies.all_host_policies()`, `deliveries = policies.all_deliveries()`, host→tenant map (`tenants.list_tenants()` then `hosts_of` each — one call per tenant), then per row `policy_status(managed, &resolve(tenant_of_row, all.get(&id).unwrap_or(&vec![])).effective.hash_hex(), row.applied_policy_hash.as_deref(), deliveries.get(&id))`. `HostSummary` gains `policy_status: String` (last field). Add a unit test `hosts_rows_carry_policy_status`.

`auth_middleware.rs`: `min_role_for` already makes non-GET under `/api/v1/groups/` Admin. Add to `tenant_route_allowed` a helper `let seg_then = |prefix: &str, suffix: &str| path.strip_prefix(prefix).and_then(|r| r.strip_suffix(suffix)).is_some_and(|s| !s.is_empty() && !s.contains('/'));` and allow: PUT and DELETE when `seg_then("/api/v1/groups/", "/policy")`; GET/HEAD when `seg_then("/api/v1/groups/", "/policy") || seg_then("/api/v1/hosts/", "/policy")`. Extend `tenant_group_allowlist_accepts_only_exact_shapes` with allowed (`GET/PUT/DELETE /api/v1/groups/g1/policy`, `GET /api/v1/hosts/h1/policy`) and denied (`POST /api/v1/groups/g1/policy`, `PUT /api/v1/hosts/h1/policy`, `GET /api/v1/groups//policy`, `GET /api/v1/groups/g1/x/policy`, `GET /api/v1/hosts/h1/policy/x`).

- [ ] **Step 3: Wiring** — `main.rs`: merge `build_policy_router(PolicyState { groups: group_store.clone(), policies: <fleet_db as Arc<dyn PolicyStore>>, registry: fleet_registry.clone(), tenants: <same as FleetState>, audit_log: audit_log.clone(), notifier: <notifier> })` before `auth_gate`; for now `let policy_notifier: Arc<dyn osiris_api::PolicyNotifier> = Arc::new(osiris_api::NoopPolicyNotifier);` shared by `FleetState`, `GroupsState` and `PolicyState` (Task 7 replaces it). Same in both composed-router harnesses and every e2e `FleetState`/`GroupsState` literal.

- [ ] **Step 4: Composed-router tests** (`composed_router_tenancy.rs`, `call(...)` helper):
  - `tenant_policy_routes_are_isolated_through_the_gate`: acme PUT policy on its own group → 200; globex PUT same → 404; acme `GET /api/v1/hosts/<globex_host>/policy` → 404; acme `POST /api/v1/groups/<gid>/policy` → 403 (gate).
  - `composed_router_auth.rs`: Viewer `PUT /api/v1/groups/<gid>/policy` → 403; Viewer `GET` → 200 (Admin creates the group first).

- [ ] **Step 5: Run** `cargo test -p osiris-api` → PASS; gates; commit:

```bash
git add crates
git commit -m "feat(api): group policy routes, host effective policy view and policy status (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Server — `PolicyReconciler`, heartbeat hash ingest, wiring

**Files:**
- Create: `crates/osiris-server/src/policy_reconcile.rs`
- Modify: `crates/osiris-server/Cargo.toml` (add `osiris-policy`), `src/lib.rs`, `src/ingest.rs`, `src/main.rs`, e2e/ingest test constructions of `IngestContext`

**Interfaces:**
- Consumes: Task 2 `CommandAction::ApplyPolicy`, `PolicyPayload::from_effective`, `CommandResult`; `osiris_response::{CommandDispatcher, DispatchError}`; Task 3 `PolicyStore`, `DeliveryRow`, `DeliveryResult`; Task 6 `osiris_api::PolicyNotifier`.
- Produces: `pub struct PolicyReconciler`; `PolicyReconciler::new(registry: Arc<dyn HostRegistry>, policies: Arc<dyn PolicyStore>, tenants: Arc<dyn TenantStore>, dispatcher: Option<Arc<dyn CommandDispatcher>>) -> Arc<Self>` (built with `Arc::new_cyclic`, keeps a `Weak<Self>`); `pub async fn reconcile_host(&self, host_id: Uuid) -> ReconcileOutcome`; `pub fn spawn_reconcile(&self, hosts: Vec<Uuid>)`; `pub enum ReconcileOutcome { Unmanaged, UnknownHost, InSync, Backoff, InFlight, Sent(DeliveryResult) }`; `impl osiris_api::PolicyNotifier for PolicyReconciler` (`hosts_changed` → `spawn_reconcile`, `managed` → dispatcher is `Some`). `IngestContext` gains `pub policy_reconciler: Arc<std::sync::OnceLock<Arc<PolicyReconciler>>>` (unset = no reconciliation).

- [ ] **Step 1: Failing tests** (in `policy_reconcile.rs`), with a scripted dispatcher:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{CommandAction, CommandResult, ExecDetail};
    use osiris_fleet::{GroupScope, HostGroupStore, HostRow, SqliteHostRegistry};
    use osiris_policy::{GroupPolicy, TelemetryLevel};
    use osiris_tenancy::SqliteTenantStore;

    #[derive(Default)]
    struct Scripted {
        sent: std::sync::Mutex<Vec<(Uuid, CommandAction, String, String)>>,
        reply: std::sync::Mutex<Option<Result<CommandResult, DispatchError>>>,
    }

    #[async_trait::async_trait] // match the attribute style osiris_response::CommandDispatcher actually uses
    impl CommandDispatcher for Scripted {
        async fn dispatch(&self, host_id: Uuid, action: CommandAction, _dry: bool, actor: String, reason: String) -> Result<CommandResult, DispatchError> {
            self.sent.lock().unwrap().push((host_id, action, actor, reason));
            self.reply.lock().unwrap().clone().unwrap_or(Ok(CommandResult::Executed { detail: ExecDetail { summary: "ok".into(), quarantine_id: None, sha256: None, signal: None } }))
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        db: Arc<SqliteHostRegistry>,
        dispatcher: Arc<Scripted>,
        rec: Arc<PolicyReconciler>,
        host: Uuid,
    }

    fn fx(managed: bool) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let tenants: Arc<dyn TenantStore> = Arc::new(SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap());
        let host = Uuid::new_v4();
        db.upsert_heartbeat(HostRow { host_id: host, hostname: "h".into(), distro: "d".into(), kernel_version: "k".into(), agent_version: "0.1.0".into(), enrolled_at: 1, last_seen: 1, health_state: osiris_health::HealthState::Healthy, cloud_provider: None, cloud_instance_id: None, cloud_region: None, applied_policy_hash: None }).unwrap();
        let dispatcher = Arc::new(Scripted::default());
        let rec = PolicyReconciler::new(db.clone(), db.clone(), tenants, managed.then(|| dispatcher.clone() as Arc<dyn CommandDispatcher>));
        Fx { _dir: dir, db, dispatcher, rec, host }
    }

    fn with_policy(f: &Fx) -> String {
        let g = f.db.create(&GroupScope::Platform, None, "g").unwrap();
        f.db.add_member(&GroupScope::Platform, g.group_id, f.host).unwrap();
        let p = GroupPolicy { telemetry_level: Some(TelemetryLevel::Minimal), ..Default::default() };
        f.db.set_policy(&GroupScope::Platform, g.group_id, &p, "u").unwrap();
        osiris_policy::EffectivePolicy { telemetry_level: Some(TelemetryLevel::Minimal), ..Default::default() }.hash_hex()
    }

    #[tokio::test]
    async fn without_a_dispatcher_nothing_is_sent() {
        let f = fx(false);
        with_policy(&f);
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::Unmanaged);
    }

    #[tokio::test]
    async fn a_host_already_in_sync_gets_nothing() {
        let f = fx(true);
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::InSync, "no policy + no applied hash");
        assert!(f.dispatcher.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mismatch_sends_a_signed_apply_policy_and_records_it() {
        let f = fx(true);
        let desired = with_policy(&f);
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::Sent(DeliveryResult::Executed));
        let sent = f.dispatcher.sent.lock().unwrap();
        let (host, action, actor, reason) = &sent[0];
        assert_eq!(*host, f.host);
        assert_eq!(actor, "policy-reconciler");
        assert_eq!(reason, &format!("effective policy {}", &desired[..12]));
        let CommandAction::ApplyPolicy { policy } = action else { panic!("wrong action") };
        assert_eq!(hex::encode(policy.policy_hash), desired);
        let d = f.db.delivery(f.host).unwrap().unwrap();
        assert_eq!((d.desired_hash.as_str(), d.last_result), (desired.as_str(), DeliveryResult::Executed));
    }

    #[tokio::test]
    async fn backoff_suppresses_resend_of_the_same_hash_within_60s() {
        let f = fx(true);
        with_policy(&f);
        *f.dispatcher.reply.lock().unwrap() = Some(Ok(CommandResult::Refused { reason: osiris_command::Refusal::Replay }));
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::Sent(DeliveryResult::Refused));
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::Backoff);
        assert_eq!(f.dispatcher.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn offline_and_timeouts_are_recorded() {
        let f = fx(true);
        with_policy(&f);
        *f.dispatcher.reply.lock().unwrap() = Some(Err(DispatchError::Offline));
        assert_eq!(f.rec.reconcile_host(f.host).await, ReconcileOutcome::Sent(DeliveryResult::Offline));
    }

    #[tokio::test]
    async fn an_unregistered_host_is_skipped() {
        let f = fx(true);
        assert_eq!(f.rec.reconcile_host(Uuid::new_v4()).await, ReconcileOutcome::UnknownHost);
    }
}
```

(If `DispatchError`/`CommandResult` are not `Clone`, store a closure or an enum tag in `Scripted` instead — keep the assertions.) Also an ingest test in `ingest.rs`: an `AGENT_HEALTH` event whose `event_data.policy_hash` is `"ab"×32` stores `applied_policy_hash = Some("abab…")`; a missing/`null`/non-64-hex value stores `None`.

- [ ] **Step 2: Implement `policy_reconcile.rs`**

```rust
//! Phase 9d-3: drives each host's applied policy toward its effective policy
//! by sending signed `ApplyPolicy` commands over the 9c channel.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_command::{CommandAction, CommandResult, PolicyPayload};
use osiris_fleet::{DeliveryResult, DeliveryRow, HostRegistry, PolicyStore};
use osiris_response::{CommandDispatcher, DispatchError};
use osiris_tenancy::TenantStore;
use uuid::Uuid;

pub const POLICY_RESEND_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome { Unmanaged, UnknownHost, InSync, Backoff, InFlight, Sent(DeliveryResult) }

pub struct PolicyReconciler {
    me: Weak<PolicyReconciler>,
    registry: Arc<dyn HostRegistry>,
    policies: Arc<dyn PolicyStore>,
    tenants: Arc<dyn TenantStore>,
    dispatcher: Option<Arc<dyn CommandDispatcher>>,
    in_flight: Mutex<HashSet<Uuid>>,
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

/// Removes the host from the in-flight set however `reconcile_host` exits.
struct InFlight<'a>(&'a Mutex<HashSet<Uuid>>, Uuid);
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.1);
    }
}

impl PolicyReconciler {
    pub fn new(registry: Arc<dyn HostRegistry>, policies: Arc<dyn PolicyStore>, tenants: Arc<dyn TenantStore>, dispatcher: Option<Arc<dyn CommandDispatcher>>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self { me: me.clone(), registry, policies, tenants, dispatcher, in_flight: Mutex::new(HashSet::new()) })
    }

    pub fn spawn_reconcile(&self, hosts: Vec<Uuid>) {
        let Some(me) = self.me.upgrade() else { return };
        for host in hosts {
            let me = me.clone();
            tokio::spawn(async move {
                let outcome = me.reconcile_host(host).await;
                tracing::debug!(%host, ?outcome, "policy reconciliation");
            });
        }
    }

    pub async fn reconcile_host(&self, host_id: Uuid) -> ReconcileOutcome {
        let Some(dispatcher) = self.dispatcher.clone() else { return ReconcileOutcome::Unmanaged };
        if !self.in_flight.lock().unwrap_or_else(|p| p.into_inner()).insert(host_id) {
            return ReconcileOutcome::InFlight;
        }
        let _guard = InFlight(&self.in_flight, host_id);

        let (registry, policies, tenants) = (self.registry.clone(), self.policies.clone(), self.tenants.clone());
        let gathered = tokio::task::spawn_blocking(move || -> Result<_, String> {
            let Some(row) = registry.get(host_id).map_err(|e| e.to_string())? else { return Ok(None) };
            let tenant = tenants.tenant_of(host_id).map_err(|e| e.to_string())?;
            let inputs = policies.policies_for_host(host_id).map_err(|e| e.to_string())?;
            let delivery = policies.delivery(host_id).map_err(|e| e.to_string())?;
            Ok(Some((row.applied_policy_hash, osiris_policy::resolve(tenant, &inputs).effective, delivery)))
        })
        .await;
        let (applied, effective, delivery) = match gathered {
            Ok(Ok(Some(v))) => v,
            Ok(Ok(None)) => return ReconcileOutcome::UnknownHost,
            Ok(Err(e)) => {
                tracing::error!(%host_id, error = %e, "policy reconciliation lookup failed");
                return ReconcileOutcome::InSync;
            }
            Err(e) => {
                tracing::error!(%host_id, error = %e, "policy reconciliation task failed");
                return ReconcileOutcome::InSync;
            }
        };
        let desired = effective.hash_hex();
        if applied.unwrap_or_else(osiris_policy::empty_policy_hash_hex) == desired {
            return ReconcileOutcome::InSync;
        }
        let now = now_ns();
        if delivery.is_some_and(|d| d.desired_hash == desired && now.saturating_sub(d.last_sent_at) < POLICY_RESEND_BACKOFF.as_nanos() as u64) {
            return ReconcileOutcome::Backoff;
        }
        let reply = dispatcher
            .dispatch(
                host_id,
                CommandAction::ApplyPolicy { policy: PolicyPayload::from_effective(&effective) },
                false,
                "policy-reconciler".into(),
                format!("effective policy {}", &desired[..12]),
            )
            .await;
        let (result, error) = match reply {
            Ok(CommandResult::Executed { .. }) | Ok(CommandResult::DryRunOk { .. }) => (DeliveryResult::Executed, None),
            Ok(CommandResult::Refused { reason }) => (DeliveryResult::Refused, Some(reason.to_string())),
            Ok(CommandResult::Failed { message, .. }) => (DeliveryResult::Failed, Some(message)),
            Err(DispatchError::Offline) => (DeliveryResult::Offline, None),
            Err(DispatchError::TimedOut) => (DeliveryResult::TimedOut, None),
            Err(other) => (DeliveryResult::Failed, Some(other.to_string())),
        };
        let row = DeliveryRow { host_id, desired_hash: desired, last_sent_at: now, last_result: result, last_error: error };
        let policies = self.policies.clone();
        match tokio::task::spawn_blocking(move || policies.record_delivery(&row)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(%host_id, error = %e, "cannot record policy delivery"),
            Err(e) => tracing::error!(%host_id, error = %e, "policy delivery record task failed"),
        }
        ReconcileOutcome::Sent(result)
    }
}

impl osiris_api::PolicyNotifier for PolicyReconciler {
    fn hosts_changed(&self, hosts: Vec<Uuid>) {
        self.spawn_reconcile(hosts);
    }

    fn managed(&self) -> bool {
        self.dispatcher.is_some()
    }
}
```

(A lookup failure is logged and reported as `InSync` so a broken store never triggers sends; the next heartbeat retries. Match `DispatchError`'s real variants; any variant other than `Offline`/`TimedOut` maps to `Failed` with its `to_string()`.)

- [ ] **Step 3: Ingest + wiring**

`ingest.rs`: in the AGENT_HEALTH hook, `let applied_policy_hash = event.event_data.get("policy_hash").and_then(|v| v.as_str()).filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).map(str::to_string);` into the `HostRow`. Collect the heartbeat host ids before the `spawn_blocking` moves `health_events`; after the registry upsert completes, `if let Some(rec) = self.policy_reconciler.get() { rec.spawn_reconcile(hosts) }`. `IngestContext` gains `pub policy_reconciler: Arc<std::sync::OnceLock<Arc<PolicyReconciler>>>`; every construction outside main passes `Arc::new(OnceLock::new())`.

`main.rs`: create `let policy_reconciler_slot = Arc::new(OnceLock::new());` before the `IngestContext` and pass it in. After `command_dispatcher` exists: `let reconciler = osiris_server::policy_reconcile::PolicyReconciler::new(fleet_registry.clone(), <fleet_db as PolicyStore>, <tenant store>, config.control.is_some().then(|| command_dispatcher.clone()));` `let _ = policy_reconciler_slot.set(reconciler.clone());` and replace Task 6's `NoopPolicyNotifier` with `reconciler.clone() as Arc<dyn osiris_api::PolicyNotifier>` (so it must be built before the routers are merged — reorder only as much as needed).

- [ ] **Step 4: Run** `cargo test -p osiris-server` → PASS; gates; commit:

```bash
git add crates
git commit -m "feat(server): policy reconciler over the signed command channel (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: CLI — `groups policy` and `hosts policy`

**Files:**
- Modify: `crates/osiris-cli/src/main.rs`

**Interfaces:**
- Consumes: Task 6 routes; existing helpers `get`, `put_json` (add via `send_json` like 9d-2's `patch_json`), `delete_empty`, `percent_encode`.
- Produces: `osiris-cli groups policy show|set|clear <group_id>`, `osiris-cli hosts policy <host_id>`.

- [ ] **Step 1: Failing parse tests** (extend `groups_cli_tests`):

```rust
    #[test]
    fn policy_subcommands_parse() {
        match parse(&["groups", "policy", "set", "g", "--level", "minimal", "--sensor", "network=off", "--sensor", "filesystem=on", "--heartbeat", "30", "--priority", "5"]).command {
            Command::Groups { action: GroupsAction::Policy { action: GroupPolicyAction::Set { group_id, level, sensor, heartbeat, priority } } } => {
                assert_eq!(group_id, "g");
                assert_eq!(level.as_deref(), Some("minimal"));
                assert_eq!(sensor, vec!["network=off".to_string(), "filesystem=on".to_string()]);
                assert_eq!(heartbeat, Some(30));
                assert_eq!(priority, Some(5));
            }
            _ => panic!("wrong variant"),
        }
        assert!(matches!(parse(&["groups", "policy", "show", "g"]).command, Command::Groups { action: GroupsAction::Policy { action: GroupPolicyAction::Show { .. } } }));
        assert!(matches!(parse(&["groups", "policy", "clear", "g"]).command, Command::Groups { action: GroupsAction::Policy { action: GroupPolicyAction::Clear { .. } } }));
        assert!(matches!(parse(&["hosts", "policy", "h"]).command, Command::Hosts { action: HostsAction::Policy { .. } }));
    }

    #[test]
    fn policy_body_is_built_from_flags() {
        let body = policy_body(Some("detailed"), &["network=off".into(), "filesystem=on".into()], Some(30), Some(5)).unwrap();
        assert_eq!(body, serde_json::json!({"telemetry_level":"DETAILED","sensors":{"network":false,"filesystem":true},"heartbeat_interval_secs":30,"priority":5}));
        assert_eq!(policy_body(None, &[], None, None).unwrap(), serde_json::json!({"sensors":{},"priority":0}));
        assert!(policy_body(Some("loud"), &[], None, None).is_err());
        assert!(policy_body(None, &["network".into()], None, None).is_err());
        assert!(policy_body(None, &["network=maybe".into()], None, None).is_err());
    }
```

- [ ] **Step 2: Implement** `GroupsAction::Policy { #[command(subcommand)] action: GroupPolicyAction }`, `enum GroupPolicyAction { Show { group_id }, Set { group_id, #[arg(long)] level: Option<String>, #[arg(long)] sensor: Vec<String>, #[arg(long)] heartbeat: Option<u64>, #[arg(long)] priority: Option<i32> }, Clear { group_id } }`, new top-level `Hosts { #[command(subcommand)] action: HostsAction }` with `enum HostsAction { Policy { host_id: String } }`, and:

```rust
/// `set` replaces the whole policy: flags not given are unset.
fn policy_body(level: Option<&str>, sensors: &[String], heartbeat: Option<u64>, priority: Option<i32>) -> Result<serde_json::Value, String> {
    let mut body = serde_json::json!({ "sensors": {}, "priority": priority.unwrap_or(0) });
    if let Some(l) = level {
        let l = l.to_ascii_lowercase();
        if !["minimal", "standard", "detailed", "forensic"].contains(&l.as_str()) {
            return Err(format!("unknown level: {l} (minimal|standard|detailed|forensic)"));
        }
        body["telemetry_level"] = serde_json::Value::String(l.to_ascii_uppercase());
    }
    for s in sensors {
        let (name, state) = s.split_once('=').ok_or_else(|| format!("--sensor expects NAME=on|off, got {s}"))?;
        let enabled = match state {
            "on" => true,
            "off" => false,
            _ => return Err(format!("--sensor expects NAME=on|off, got {s}")),
        };
        body["sensors"][name] = serde_json::Value::Bool(enabled);
    }
    if let Some(h) = heartbeat {
        body["heartbeat_interval_secs"] = serde_json::json!(h);
    }
    Ok(body)
}
```

Dispatch: `show` → `GET /api/v1/groups/<g>/policy`; `set` → `policy_body(...)` then `PUT` JSON (add `put_json` via `send_json(client.put(url).json(&body), ...)`); `clear` → `DELETE`; `hosts policy` → `GET /api/v1/hosts/<h>/policy`. Server-side validation errors surface through the existing non-2xx handling.

- [ ] **Step 3: Run** `cargo test -p osiris-cli` → PASS; gates; commit:

```bash
git add crates/osiris-cli
git commit -m "feat(cli): groups policy and hosts policy subcommands (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Console — group Policy section and host policy status

**Files:**
- Modify: `console/src/api/types.ts`, `client.ts`, `hooks.ts`; `console/src/screens/groups/GroupDetail.tsx` (+ test); `console/src/screens/hosts/HostList.tsx` (+ test)
- Create: `console/src/screens/groups/GroupPolicyEditor.tsx`, `GroupPolicyEditor.test.tsx`, `console/src/screens/hosts/HostPolicyPanel.tsx`, `HostPolicyPanel.test.tsx`

**Interfaces:**
- Consumes: Task 6 JSON (`GET/PUT/DELETE /api/v1/groups/:id/policy` → `{"policy": GroupPolicy|null}`; `GET /api/v1/hosts/:id/policy` → HostPolicyView; `/hosts` rows `policy_status`).
- Produces: TS types `TelemetryLevel = "MINIMAL"|"STANDARD"|"DETAILED"|"FORENSIC"`, `GroupPolicy { telemetry_level?: TelemetryLevel | null; sensors: Record<string, boolean>; heartbeat_interval_secs?: number | null; priority: number }`, `PolicyStatus = "IN_SYNC"|"PENDING"|"FAILED"|"UNMANAGED"`, `PolicySource { tier: "PLATFORM"|"TENANT"; group_id?: string; group_name?: string | null }`, `HostPolicyView { host_id; effective: {telemetry_level: TelemetryLevel|null; sensors: Record<string, boolean>; heartbeat_interval_secs: number|null}; sources: { telemetry_level?: PolicySource; sensors: Record<string, PolicySource>; heartbeat_interval_secs?: PolicySource }; desired_hash: string; applied_hash: string|null; status: PolicyStatus; last_delivery: {sent_at: number; result: string; error: string|null} | null }`; `HostSummary.policy_status: PolicyStatus`; client `fetchGroupPolicy`, `putGroupPolicy`, `deleteGroupPolicy`, `fetchHostPolicy`; hooks `useGroupPolicy(id)`, `useSaveGroupPolicy(id)`, `useClearGroupPolicy(id)`, `useHostPolicy(hostId)` (mutations invalidate `["group-policy", id]`, `["hosts"]`, `["host-policy"]`). Sensor list constant `KNOWN_SENSORS` (same 7 names).

- [ ] **Step 1: Client + hooks** with tests in `client.test.ts` in the existing style: `putGroupPolicy("g", policy)` → `fetch("/api/v1/groups/g/policy", {method:"PUT", headers:{"Content-Type":"application/json"}, body: JSON.stringify(policy)})`; `deleteGroupPolicy("g")` → `{method:"DELETE"}` resolving `undefined` on 204; `fetchHostPolicy("h")` → `/api/v1/hosts/h/policy`. Add `apiPut` with a body variant if the 9d-2 `apiPut` takes none (`request<T>("PUT", path, body)`).

- [ ] **Step 2: `GroupPolicyEditor`** — props `{ groupId: string; memberCount: number }`. Renders "Policy" heading; loading/error states; for non-Admins a read-only summary (level or "Not set", each sensor On/Off/Not set, heartbeat, priority, or "No policy"). For Admins a form: `<select aria-label="Telemetry level">` (Not set + 4 levels), for each of the 7 sensors a `<select aria-label="Sensor <name>">` (Not set / On / Off), `<input aria-label="Heartbeat (seconds)" type="number">`, `<input aria-label="Priority" type="number">`, buttons "Save policy" and "Remove policy". Saving builds a `GroupPolicy` (omit "Not set" fields; sensors only for On/Off). If the new policy turns any sensor Off or sets the level to MINIMAL, the first click shows `This reduces visibility on {memberCount} hosts.` with "Confirm save" / "Cancel"; only "Confirm save" calls the mutation. API errors render inline with `role="alert"` (400 → the server's message: strip the `PUT … failed with status 400: ` prefix the client adds, keeping only the body text).

Tests (`GroupPolicyEditor.test.tsx`, hooks mocked as in `GroupDetail.test.tsx`): renders existing policy values into the controls; Admin save of a Standard-level policy calls `mutate({ telemetry_level: "STANDARD", sensors: {}, priority: 0 }, expect.anything())` immediately; turning `network` Off shows the warning with the member count and does not call `mutate` until "Confirm save"; "Remove policy" calls the clear mutation; Viewer sees no form controls and "No policy" when `policy` is null; a 400 `ApiError` shows its message.

- [ ] **Step 3: Mount** `<GroupPolicyEditor groupId={g.group_id} memberCount={g.member_count} />` in `GroupDetail.tsx` below the members table (update `GroupDetail.test.tsx` mocks for the new hooks).

- [ ] **Step 4: Hosts** — `HostList.tsx` gains a "Policy" column: a button showing `row.policy_status` (text as-is); clicking toggles `<HostPolicyPanel hostId={row.host_id} />` under the table. `HostPolicyPanel` shows status, level/sensors/heartbeat with their source (`Platform policy` for `{tier:"PLATFORM"}` without a name, else `Group <group_name>`), and the last delivery (`result` + `error`). Tests: the column renders each status; the panel renders a platform-opaque source as "Platform policy" and a tenant source as "Group web"; FAILED shows the delivery error. Add `policy_status: "IN_SYNC"` to existing host fixtures.

- [ ] **Step 5: Run** in `console/`: `npx vitest run` and `npm run build` → green; commit:

```bash
git add console
git commit -m "feat(console): group policy editor and host policy status (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: End-to-end and operator docs

**Files:**
- Create: `crates/osiris-e2e-tests/tests/policy_distribution.rs`, `docs/operators-fleet-policy.md`
- Modify: `docs/ROADMAP-REMAINING.md` (§9d: 9d-3 delivered; Fleet Manager complete)

**Interfaces:**
- Consumes: everything above; the PKI/mTLS/command-key setup in `crates/osiris-e2e-tests/tests/control_channel.rs` (`Harness::start`) and the real-Agent fleet harness (`spawn_fleet_harness`, `wait_for_host_online`) in `end_to_end.rs`.

- [ ] **Step 1: Scenario** `a_group_policy_reaches_a_real_agent_and_reports_in_sync`:
  1. Generate the server/agent certs and the command signing key exactly as `control_channel.rs` does; start a real `ControlListener` + `ControlHub` + `HubDispatcher`.
  2. Start the real ingest stack + a `PolicyReconciler` (dispatcher = the hub dispatcher) installed into the `IngestContext`'s slot, and the composed router (groups, fleet, policy routers merged before `auth_gate`, notifier = the reconciler).
  3. Start a real `Agent` with `fleet.health_interval_secs = 1`, the synthetic sensor enabled, and `control: Some(ControlConfig { .. })` pointing at the listener with the generated material; wait for the host ONLINE (existing bounded poll helper).
  4. Admin: `POST /api/v1/groups {"name":"e2e"}`, `PUT .../members/<host>`, `PUT /api/v1/groups/<gid>/policy {"telemetry_level":"MINIMAL","sensors":{"network":false},"heartbeat_interval_secs":10}` → 200.
  5. Bounded poll (≤ 15 s, 200 ms) on `GET /api/v1/hosts/<host>/policy` until `status == "IN_SYNC"`; assert `effective.telemetry_level == "MINIMAL"` and `applied_hash == desired_hash`; assert the agent's overlay file `{spool}.policy.json` exists.
  6. `DELETE /api/v1/groups/<gid>/policy` → 204; poll until `status == "IN_SYNC"` again with `applied_hash == null`; the overlay file is gone.
  7. Shut down the agent and the ingest loop.
  If a helper you need is private to another test file, move it into a small shared module under `crates/osiris-e2e-tests/tests/common/mod.rs` and use it from both files (do not duplicate the PKI setup).

- [ ] **Step 2: Docs** — `docs/operators-fleet-policy.md`: what each field does; the level table (copy spec §3.3); precedence (platform > tenant, priority, tie-break); that a sensor only runs if `agent.yaml` configures it; the overlay file location and that deleting it makes the server re-send; status meanings; that agents without a control channel show `UNMANAGED`; CLI examples. Update `docs/ROADMAP-REMAINING.md` §9d.

- [ ] **Step 3: Run** `cargo build -p osiris-cli -p osiris-server -p osiris-agent && cargo test -p osiris-e2e-tests` → all green; gates; commit:

```bash
git add crates/osiris-e2e-tests docs
git commit -m "test(e2e): group policy reaches a real agent over the signed channel; operator docs (Phase 9d-3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
