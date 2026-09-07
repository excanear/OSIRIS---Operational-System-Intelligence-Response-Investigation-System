use uuid::Uuid;

use osiris_schema::{
    CanonicalEvent, Category, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
    ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
};
use osiris_sensor_api::{
    DnsEventRaw, FileEventRaw, FileOperation, NetworkDirection as RawNetworkDirection,
    NetworkEventRaw, NetworkOperation, ProcessExecRaw, RawEvent, RawEventSource,
};

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
        RawEvent::Network(n) => normalize_network_event(n, host, boot_id),
        RawEvent::Dns(d) => normalize_dns_event(d, host, boot_id),
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

/// A small helper: builds the provisional `ProcessRef` file/network/DNS
/// events share (start_time 0, replaced by Enrich once the real exec event
/// is known) — `None` when the raw record carries no pid at all (Global
/// Constraint #5), rather than minting a key for a process nobody observed.
fn provisional_process(
    pid: Option<u32>,
    exe_path: &str,
    host_id: uuid::Uuid,
    boot_id: &str,
) -> Option<ProcessRef> {
    let pid = pid?;
    Some(ProcessRef {
        process_key: ProcessKey::new(host_id, boot_id, pid, 0),
        pid,
        exe_path: exe_path.to_string(),
        cmdline: vec![],
        exe_hash: None,
        start_time_mono: 0,
    })
}

fn normalize_network_event(raw: NetworkEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "network_sensor/audit",
        RawEventSource::Synthetic => "network_sensor/synthetic",
    };
    let event_type = match raw.operation {
        NetworkOperation::Connect => EventType::NetworkConnect,
        NetworkOperation::Accept => EventType::NetworkAccept,
        NetworkOperation::Close => EventType::NetworkClose,
    };
    let direction = match raw.direction {
        RawNetworkDirection::Outbound => NetworkDirection::Outbound,
        RawNetworkDirection::Inbound => NetworkDirection::Inbound,
    };
    // Outbound: this host dialed out, so local is the source and remote is
    // the destination. Inbound: the remote peer initiated, so it is
    // recorded as the source and this host as the destination — matching
    // conventional "who is talking to whom" network-log semantics rather
    // than "which side is local."
    let (src_ip, src_port, dst_ip, dst_port) = match direction {
        NetworkDirection::Outbound => {
            (raw.local_addr.clone(), raw.local_port, raw.remote_addr.clone(), raw.remote_port)
        }
        NetworkDirection::Inbound => {
            (raw.remote_addr.clone(), raw.remote_port, raw.local_addr.clone(), raw.local_port)
        }
    };
    let process = provisional_process(raw.pid, &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: uuid::Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type,
        category: Category::Network,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: Some(NetworkRef {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto: raw.proto,
            direction,
            bytes: None,
        }),
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
        event_data: serde_json::json!({ "comm": raw.comm, "uid": raw.uid }),
    }
}

fn normalize_dns_event(raw: DnsEventRaw, host: &HostRef, boot_id: &str) -> CanonicalEvent {
    let source = match raw.source {
        RawEventSource::Audit => Source::Audit,
        RawEventSource::Synthetic => Source::Synthetic,
    };
    let provider = match raw.source {
        RawEventSource::Audit => "dns_sensor/audit",
        RawEventSource::Synthetic => "dns_sensor/synthetic",
    };
    let process = provisional_process(raw.pid, &raw.exe_path, host.host_id, boot_id);
    CanonicalEvent {
        event_id: uuid::Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host.host_id,
        boot_id: boot_id.to_string(),
        timestamp: raw.timestamp_ns,
        monotonic_timestamp: raw.timestamp_ns,
        event_type: EventType::DnsQuery,
        category: Category::Dns,
        severity: Severity::Info,
        host: host.clone(),
        user: None,
        session: None,
        process,
        parent_process: None,
        thread: None,
        file: None,
        network: None,
        dns: Some(DnsRef {
            query: raw.query,
            qtype: raw.qtype,
            response_ips: raw.response_ips,
            ttl: raw.ttl,
        }),
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
        event_data: serde_json::json!({ "comm": raw.comm, "uid": raw.uid }),
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

    fn network_raw(
        operation: osiris_sensor_api::NetworkOperation,
        pid: Option<u32>,
    ) -> osiris_sensor_api::NetworkEventRaw {
        osiris_sensor_api::NetworkEventRaw {
            operation,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: "203.0.113.50".to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_sensor_api::NetworkDirection::Outbound,
            pid,
            uid: 1000,
            exe_path: if pid.is_some() {
                "/usr/bin/curl".to_string()
            } else {
                String::new()
            },
            comm: if pid.is_some() {
                "curl".to_string()
            } else {
                String::new()
            },
            timestamp_ns: 1_690_000_005_000_000_000,
            source: RawEventSource::Audit,
        }
    }

    fn dns_raw(pid: Option<u32>) -> osiris_sensor_api::DnsEventRaw {
        osiris_sensor_api::DnsEventRaw {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
            pid,
            uid: 1000,
            exe_path: if pid.is_some() {
                "/usr/bin/curl".to_string()
            } else {
                String::new()
            },
            comm: if pid.is_some() { "curl".to_string() } else { String::new() },
            timestamp_ns: 1_690_000_004_000_000_000,
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn network_operations_map_to_the_matching_event_type_and_network_category() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        for (operation, expected) in [
            (NetworkOperation::Connect, EventType::NetworkConnect),
            (NetworkOperation::Accept, EventType::NetworkAccept),
            (NetworkOperation::Close, EventType::NetworkClose),
        ] {
            let event = normalize(
                RawEvent::Network(network_raw(operation, Some(300))),
                &host,
                "boot-1",
            );
            assert_eq!(event.event_type, expected);
            assert_eq!(event.category, Category::Network);
        }
    }

    #[test]
    fn network_event_carries_a_complete_network_ref_for_an_outbound_connection() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, Some(300))),
            &host,
            "boot-1",
        );
        let net = event.network.expect("network events must carry a NetworkRef");
        // Outbound: local is the source, remote is the destination.
        assert_eq!(net.src_ip, "10.0.0.5");
        assert_eq!(net.src_port, 51000);
        assert_eq!(net.dst_ip, "203.0.113.50");
        assert_eq!(net.dst_port, 443);
        assert_eq!(net.direction, osiris_schema::NetworkDirection::Outbound);
        assert_eq!(event.provider, "network_sensor/audit");
    }

    #[test]
    fn network_event_with_no_pid_attribution_carries_no_process() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, None)),
            &host,
            "boot-1",
        );
        assert!(
            event.process.is_none(),
            "a connection the sensor could not attribute must carry no process, not a fabricated one"
        );
        assert!(event.network.is_some(), "the NetworkRef itself is still populated");
    }

    #[test]
    fn network_event_process_key_is_provisional_with_a_zero_start_time_when_pid_is_known() {
        use osiris_sensor_api::NetworkOperation;
        let host = sample_host();
        let event = normalize(
            RawEvent::Network(network_raw(NetworkOperation::Connect, Some(300))),
            &host,
            "boot-1",
        );
        let process = event.process.expect("pid was known, so process must be set");
        assert_eq!(process.pid, 300);
        assert_eq!(process.start_time_mono, 0);
        assert_eq!(
            process.process_key,
            ProcessKey::new(host.host_id, "boot-1", 300, 0)
        );
    }

    #[test]
    fn dns_query_normalizes_to_correct_event_type_and_dns_category() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(Some(300))), &host, "boot-1");
        assert_eq!(event.event_type, EventType::DnsQuery);
        assert_eq!(event.category, Category::Dns);
        assert_eq!(event.provider, "dns_sensor/audit");
    }

    #[test]
    fn dns_event_carries_a_complete_dns_ref() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(Some(300))), &host, "boot-1");
        let dns = event.dns.expect("DNS events must carry a DnsRef");
        assert_eq!(dns.query, "cdn-assets.xyz");
        assert_eq!(dns.qtype, "A");
        assert_eq!(dns.response_ips, vec!["203.0.113.50".to_string()]);
        assert_eq!(dns.ttl, Some(300));
    }

    #[test]
    fn dns_event_with_no_pid_attribution_carries_no_process() {
        let host = sample_host();
        let event = normalize(RawEvent::Dns(dns_raw(None)), &host, "boot-1");
        assert!(event.process.is_none());
        assert!(event.dns.is_some());
    }
}
