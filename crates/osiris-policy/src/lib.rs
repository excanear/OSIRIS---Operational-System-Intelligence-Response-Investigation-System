//! Group policy model for Fleet Manager policy distribution (Phase 9d-3).
//! Pure: no I/O. Shared by the server (resolution, reconciliation) and the
//! agent (validation, filtering, hashing) so both sides agree byte-for-byte.

use std::collections::BTreeMap;

use osiris_schema::EventType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const KNOWN_SENSORS: [&str; 7] = [
    "container",
    "filesystem",
    "identity",
    "network",
    "persistence",
    "process_exec",
    "systemd",
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

fn validate_fields(
    sensors: &BTreeMap<String, bool>,
    heartbeat: Option<u64>,
) -> Result<(), PolicyError> {
    if let Some(name) = sensors
        .keys()
        .find(|n| !KNOWN_SENSORS.contains(&n.as_str()))
    {
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
        self.telemetry_level.is_none()
            && self.sensors.is_empty()
            && self.heartbeat_interval_secs.is_none()
    }

    pub fn hash(&self) -> [u8; 32] {
        let sensors: Vec<(&str, bool)> =
            self.sensors.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        let mut hasher = Sha256::new();
        hasher.update(b"osiris-policy-v1\0");
        hasher.update(encode_fields(
            self.telemetry_level,
            &sensors,
            self.heartbeat_interval_secs,
        ));
        hasher.finalize().into()
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }
}

/// The field encoding shared by the policy hash and the signed
/// `ApplyPolicy` command. `sensors` must already be in the order to encode.
pub fn encode_fields(
    level: Option<TelemetryLevel>,
    sensors: &[(&str, bool)],
    heartbeat: Option<u64>,
) -> Vec<u8> {
    let mut o = Vec::new();
    o.push(level.map_or(0, TelemetryLevel::code));
    o.extend_from_slice(
        &u32::try_from(sensors.len())
            .expect("sensor count fits u32")
            .to_be_bytes(),
    );
    for (name, enabled) in sensors {
        o.extend_from_slice(
            &u32::try_from(name.len())
                .expect("name fits u32")
                .to_be_bytes(),
        );
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
        ProcessExec
        | ProcessExit
        | PrivilegeUidChange
        | PrivilegeGidChange
        | PrivilegeCapabilityChange
        | PrivilegeSudo
        | PrivilegeSetuid
        | SessionLogin
        | SessionLogout
        | PersistenceCreated
        | PersistenceModified
        | PersistenceRemoved
        | ServiceCreate
        | ServiceModify
        | ServiceDelete
        | ModuleLoad
        | ModuleUnload
        | ContainerCreate
        | ContainerStart
        | ContainerStop
        | ContainerDestroy
        | LsmDenial => Some(Minimal),
        ProcessFork | SessionCreate | SessionTerminate | ServiceStart | ServiceStop
        | TimerCreate | TimerModify | NetworkConnect | NetworkAccept | NetworkClose | DnsQuery
        | FileCreate | FileDelete | FileRename | FileMove | FileExecute | FilePermissionChange
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
        let source = FieldSource {
            group_id: input.group_id,
            tier,
        };
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

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use osiris_schema::EventType;

    fn gid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn input(n: u128, tenant: Option<Uuid>, p: GroupPolicy) -> GroupPolicyInput {
        GroupPolicyInput {
            group_id: gid(n),
            group_tenant: tenant,
            policy: p,
        }
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
        for t in [
            EventType::AgentHealth,
            EventType::SensorHealth,
            EventType::AgentStart,
            EventType::AgentStop,
        ] {
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
        assert_eq!(
            PolicyError::UnknownSensor("dns".into()).to_string(),
            "unknown sensor: dns"
        );
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
        let tenant_a = GroupPolicy {
            telemetry_level: Some(TelemetryLevel::Forensic),
            priority: 1000,
            ..Default::default()
        };
        let stale_b = GroupPolicy {
            heartbeat_interval_secs: Some(10),
            ..Default::default()
        };
        let platform = GroupPolicy {
            telemetry_level: Some(TelemetryLevel::Minimal),
            priority: -5,
            ..Default::default()
        };
        let r = resolve(
            Some(a),
            &[
                input(1, Some(a), tenant_a),
                input(2, Some(b), stale_b),
                input(3, None, platform),
            ],
        );
        assert_eq!(r.effective.telemetry_level, Some(TelemetryLevel::Minimal));
        assert_eq!(
            r.level_source,
            Some(FieldSource {
                group_id: gid(3),
                tier: PolicyTier::Platform
            })
        );
        assert_eq!(
            r.effective.heartbeat_interval_secs, None,
            "tenant b's group no longer applies"
        );
    }

    #[test]
    fn priority_orders_within_a_tier_and_ties_break_by_group_id() {
        let t = Some(Uuid::from_u128(100));
        let low = GroupPolicy {
            telemetry_level: Some(TelemetryLevel::Standard),
            priority: 1,
            ..Default::default()
        };
        let high = GroupPolicy {
            telemetry_level: Some(TelemetryLevel::Detailed),
            priority: 5,
            ..Default::default()
        };
        assert_eq!(
            resolve(t, &[input(1, t, low.clone()), input(2, t, high)])
                .effective
                .telemetry_level,
            Some(TelemetryLevel::Detailed)
        );
        let tie_a = GroupPolicy {
            heartbeat_interval_secs: Some(30),
            ..Default::default()
        };
        let tie_b = GroupPolicy {
            heartbeat_interval_secs: Some(60),
            ..Default::default()
        };
        assert_eq!(
            resolve(t, &[input(9, t, tie_b), input(4, t, tie_a)])
                .effective
                .heartbeat_interval_secs,
            Some(30)
        );
    }

    #[test]
    fn fields_resolve_independently() {
        let t = Some(Uuid::from_u128(100));
        let mut first = GroupPolicy {
            priority: 10,
            ..Default::default()
        };
        first.sensors.insert("network".into(), false);
        let mut second = GroupPolicy {
            telemetry_level: Some(TelemetryLevel::Standard),
            priority: 1,
            ..Default::default()
        };
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
        let mut p = EffectivePolicy {
            telemetry_level: Some(TelemetryLevel::Standard),
            heartbeat_interval_secs: Some(30),
            ..Default::default()
        };
        p.sensors.insert("network".into(), false);
        let h1 = p.hash();
        assert_eq!(h1, p.clone().hash());
        let mut q = p.clone();
        q.sensors.insert("network".into(), true);
        assert_ne!(h1, q.hash());
        assert_eq!(p.hash_hex().len(), 64);
        assert_eq!(
            EffectivePolicy::default().hash_hex(),
            empty_policy_hash_hex()
        );
        assert!(EffectivePolicy::default().is_empty());
        assert!(!p.is_empty());
    }

    #[test]
    fn level_serializes_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&TelemetryLevel::Detailed).unwrap(),
            "\"DETAILED\""
        );
    }
}
