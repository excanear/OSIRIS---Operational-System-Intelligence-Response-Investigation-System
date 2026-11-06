//! Shared fixtures for transport unit tests.

use std::sync::Arc;

use osiris_schema::*;
use uuid::Uuid;

use crate::record::ExportRecord;

pub fn event_with_exe(n: u8, exe: &str) -> Arc<ExportRecord> {
    let host_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
    let et = EventType::ProcessExec;
    let e = CanonicalEvent {
        event_id: Uuid::parse_str(&format!("aaaaaaaa-0000-4000-8000-{n:012}")).unwrap(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id,
        boot_id: "boot-1".to_string(),
        timestamp: 1_762_300_800_123_456_789,
        monotonic_timestamp: 5_000,
        event_type: et,
        category: et.category(),
        severity: Severity::High,
        host: HostRef {
            host_id,
            hostname: "web-01".to_string(),
            distro: "ubuntu-24.04".to_string(),
            kernel_version: "6.8.0".to_string(),
            cloud: None,
        },
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key: ProcessKey::new(host_id, "boot-1", 42, 5_000),
            pid: 42,
            exe_path: exe.to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 5_000,
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
        provider: "test".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    };
    Arc::new(ExportRecord::Event(e))
}

pub fn event(n: u8) -> Arc<ExportRecord> {
    event_with_exe(n, "/usr/bin/curl")
}
