use uuid::Uuid;

use osiris_schema::{
    CanonicalEvent, Category, EventType, FileRef, HostRef, ProcessKey, ProcessRef, Severity,
    Source, SCHEMA_VERSION,
};
use osiris_sensor_api::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};

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
        RawEvent::File(f) => normalize_file_event(f, host, boot_id),
        other => panic!(
            "the Normalize stage must only handle ProcessExec and File events, got {other:?}"
        ),
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

fn normalize_file_event(raw: FileEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "filesystem_sensor/audit",
        RawEventSource::Synthetic => "filesystem_sensor/synthetic",
    };
    let event_type = match raw.operation {
        FileOperation::Create => EventType::FileCreate,
        FileOperation::Write => EventType::FileWrite,
        FileOperation::Delete => EventType::FileDelete,
        FileOperation::Rename => EventType::FileRename,
    };
    // Provisional identity, replaced by the Enrich stage's ProcessResolver
    // lookup whenever this pid's PROCESS_EXEC has been seen. `0` is used
    // rather than the event timestamp so the placeholder is obviously not a
    // real start time, and so two file events from the same process hash to
    // one provisional key instead of one key per event.
    let process_key = ProcessKey::new(host.host_id, boot_id, raw.pid, 0);
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::File,
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
            start_time_mono: 0,
        }),
        parent_process: None,
        thread: None,
        file: Some(FileRef {
            path: raw.path,
            previous_path: raw.previous_path,
            inode: raw.inode,
            device_id: raw.device_id,
            size: None,
            mode: raw.mode,
            owner_uid: raw.owner_uid,
            owner_gid: raw.owner_gid,
            hash: None,
        }),
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
        event_data: serde_json::json!({
            "comm": raw.comm,
            "ppid": raw.ppid,
            "uid": raw.uid,
            "audit_serial": raw.audit_serial,
        }),
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

    fn file_raw(operation: osiris_sensor_api::FileOperation) -> osiris_sensor_api::FileEventRaw {
        osiris_sensor_api::FileEventRaw {
            operation,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn file_operations_map_to_the_matching_event_type_and_file_category() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        for (operation, expected) in [
            (FileOperation::Create, EventType::FileCreate),
            (FileOperation::Write, EventType::FileWrite),
            (FileOperation::Delete, EventType::FileDelete),
            (FileOperation::Rename, EventType::FileRename),
        ] {
            let event = normalize(RawEvent::File(file_raw(operation)), &host, "boot-1");
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::File);
        }
    }

    #[test]
    fn file_event_carries_a_complete_file_ref() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Create)),
            &host,
            "boot-1",
        );
        let file = event.file.expect("file events must carry a FileRef");
        assert_eq!(file.path, "/var/www/html/shell.php");
        assert_eq!(file.inode, Some(131075));
        assert_eq!(file.device_id, Some(osiris_schema::encode_device_id(8, 1)));
        assert_eq!(file.owner_uid, Some(33));
        assert_eq!(event.provider, "filesystem_sensor/audit");
        assert_eq!(event.source, Source::Audit);
    }

    #[test]
    fn rename_carries_the_previous_path() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let mut raw = file_raw(FileOperation::Rename);
        raw.previous_path = Some("/var/www/html/.shell.php.tmp".to_string());
        let event = normalize(RawEvent::File(raw), &host, "boot-1");
        assert_eq!(
            event.file.unwrap().previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
    }

    /// The acting process's identity is minted by its PROCESS_EXEC event,
    /// the only record carrying the real start time that `process_key`
    /// hashes. A file event has no access to that, so normalize
    /// deliberately mints a *provisional* key (start_time 0) which the
    /// Enrich stage replaces with the authoritative one. Hashing the file
    /// event's own timestamp in here instead would silently produce a
    /// different key for the same process.
    #[test]
    fn file_event_process_key_is_provisional_with_a_zero_start_time() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Write)),
            &host,
            "boot-1",
        );
        let process = event
            .process
            .expect("file events must name the acting process");
        assert_eq!(process.pid, 300);
        assert_eq!(process.exe_path, "/usr/bin/curl");
        assert_eq!(process.start_time_mono, 0);
        assert_eq!(
            process.process_key,
            ProcessKey::new(host.host_id, "boot-1", 300, 0)
        );
    }

    /// §9.4 says relationships are computed once, at *enrichment* time —
    /// normalize must not pre-populate an edge whose `from` cites the
    /// provisional key it is about to have overwritten.
    #[test]
    fn normalize_does_not_yet_attach_relationships() {
        use osiris_sensor_api::FileOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::File(file_raw(FileOperation::Create)),
            &host,
            "boot-1",
        );
        assert!(event.relationships.is_empty());
    }
}
