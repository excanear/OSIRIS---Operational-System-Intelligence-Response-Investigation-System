use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::*;
use crate::event_type::{Category, EventType, Severity, Source};
use crate::relationships::EntityRelationship;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub event_id: Uuid,
    pub schema_version: String,
    pub host_id: Uuid,
    pub boot_id: String,

    pub timestamp: u64,
    pub monotonic_timestamp: u64,

    pub event_type: EventType,
    pub category: Category,
    pub severity: Severity,

    pub host: HostRef,
    pub user: Option<UserRef>,
    pub session: Option<SessionRef>,
    pub process: Option<ProcessRef>,
    pub parent_process: Option<ProcessRef>,
    pub thread: Option<ThreadRef>,
    pub file: Option<FileRef>,
    pub network: Option<NetworkRef>,
    pub dns: Option<DnsRef>,
    pub device: Option<DeviceRef>,
    pub service: Option<ServiceRef>,
    pub container: Option<ContainerRef>,
    pub namespace: Option<NamespaceRef>,
    pub cgroup: Option<CgroupRef>,
    pub kernel: Option<KernelRef>,

    pub source: Source,
    pub provider: String,
    pub raw_event: Option<Vec<u8>>,

    pub relationships: Vec<EntityRelationship>,
    pub tags: Vec<String>,
    pub risk: Option<RiskAnnotation>,

    /// Typed per event_type by the sensor that emits it — no sensor exists
    /// yet in Phase 0 (§29), so the concrete payload shapes arrive with the
    /// Phase 1 Process+Exec sensor. Kept untyped here deliberately.
    pub event_data: serde_json::Value,
}

impl CanonicalEvent {
    pub fn schema_version_matches(&self, expected: &str) -> bool {
        self.schema_version == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_key::ProcessKey;

    fn sample_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "boot-1".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 123_456_789,
            event_type: EventType::ProcessExec,
            category: EventType::ProcessExec.category(),
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "test-host".to_string(),
                distro: "ubuntu-24.04".to_string(),
                kernel_version: "6.8.0".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "boot-1", 4242, 123_456_789),
                pid: 4242,
                exe_path: "/usr/bin/curl".to_string(),
                cmdline: vec!["curl".to_string(), "https://example.com".to_string()],
                exe_hash: None,
                start_time_mono: 123_456_789,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Ebpf,
            provider: "exec_sensor/ebpf".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: CanonicalEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_id, back.event_id);
        assert_eq!(
            event.process.as_ref().unwrap().process_key,
            back.process.as_ref().unwrap().process_key
        );
    }

    #[test]
    fn schema_version_check() {
        let event = sample_event();
        assert!(event.schema_version_matches(SCHEMA_VERSION));
        assert!(!event.schema_version_matches("2.0"));
    }
}
