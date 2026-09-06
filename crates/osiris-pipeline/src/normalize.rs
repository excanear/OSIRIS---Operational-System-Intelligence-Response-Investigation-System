use uuid::Uuid;

use osiris_schema::{
    CanonicalEvent, Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source,
    SCHEMA_VERSION,
};
use osiris_sensor_api::{ProcessExecRaw, RawEvent, RawEventSource};

/// Maps a RawEvent to a CanonicalEvent (ARCHITECTURE.md §7.1 step 2).
/// `boot_id` is threaded in here (not left to the Enrich stage) because
/// `process_key`'s hash requires it (ARCHITECTURE.md §9.2) — the envelope's
/// `boot_id` field itself is still considered "attached" here for that same
/// reason, ahead of Enrich's other, cross-event work (parent_process
/// resolution) in §7.1 step 3. `parent_process` is left unset here and
/// filled in by the Enrich stage.
pub fn normalize(raw: RawEvent, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    match raw {
        RawEvent::ProcessExec(p) => normalize_process_exec(p, host, boot_id),
    }
}

fn normalize_process_exec(raw: ProcessExecRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "process_exec_sensor/audit",
        RawEventSource::Synthetic => "process_exec_sensor/synthetic",
    };
    let process_key = ProcessKey::new(host.host_id, boot_id, raw.pid, raw.start_time_mono);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.start_time_mono,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key,
            pid: raw.pid,
            exe_path: raw.exe_path,
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: raw.start_time_mono,
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
        source,
        provider: provider.to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({ "comm": raw.comm, "ppid": raw.ppid, "uid": raw.uid }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "test-host".to_string(),
            distro: "test-distro".to_string(),
            kernel_version: "0.0.0".to_string(),
            cloud: None,
        }
    }

    #[test]
    fn process_exec_normalizes_to_correct_event_type_and_category() {
        let host = sample_host();
        let raw = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 4242,
            ppid: 100,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            start_time_mono: 123_456,
            source: RawEventSource::Audit,
        });
        let event = normalize(raw, &host, "boot-1");
        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.category, Category::Process);
        assert_eq!(event.source, Source::Audit);
        assert_eq!(event.boot_id, "boot-1");
        assert_eq!(event.process.unwrap().exe_path, "/usr/bin/curl");
    }

    #[test]
    fn synthetic_source_maps_correctly() {
        let host = sample_host();
        let raw = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe_path: "/bin/init".to_string(),
            comm: "init".to_string(),
            timestamp_ns: 1,
            start_time_mono: 1,
            source: RawEventSource::Synthetic,
        });
        let event = normalize(raw, &host, "boot-1");
        assert_eq!(event.source, Source::Synthetic);
        assert_eq!(event.provider, "process_exec_sensor/synthetic");
    }
}
