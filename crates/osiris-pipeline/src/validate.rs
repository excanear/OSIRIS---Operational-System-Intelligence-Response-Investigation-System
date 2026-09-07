use osiris_schema::CanonicalEvent;

/// Validate stage (ARCHITECTURE.md §7.1 step 4): a failing event is never
/// silently dropped — it is tagged INVALID and still forwarded, so an
/// operator can see what's malformed rather than have a silent gap.
/// Returns true if the event was valid (no tag added).
pub fn validate(event: &mut CanonicalEvent) -> bool {
    use osiris_schema::EventType::{
        DnsQuery, FileCreate, FileDelete, FileRename, FileWrite, NetworkAccept, NetworkClose,
        NetworkConnect,
    };
    let mut valid = true;
    if event.host_id.is_nil() {
        valid = false;
    }
    if event.timestamp == 0 {
        valid = false;
    }
    if event.event_type == osiris_schema::EventType::ProcessExec && event.process.is_none() {
        valid = false;
    }
    if matches!(
        event.event_type,
        FileCreate | FileWrite | FileDelete | FileRename
    ) {
        // A file event with no path names nothing — it cannot be stored,
        // queried by a File Story, or explained in an alert.
        let has_path = event
            .file
            .as_ref()
            .map(|f| !f.path.trim().is_empty())
            .unwrap_or(false);
        if !has_path {
            valid = false;
        }
        if event.event_type == FileRename
            && event
                .file
                .as_ref()
                .and_then(|f| f.previous_path.as_deref())
                .map(|p| p.trim().is_empty())
                .unwrap_or(true)
        {
            valid = false;
        }
    }
    if matches!(
        event.event_type,
        NetworkConnect | NetworkAccept | NetworkClose
    ) {
        // A network event with no remote address names no connection — it
        // cannot be queried by a Network Story or explained in an alert.
        let has_remote = event
            .network
            .as_ref()
            .map(|n| !n.dst_ip.trim().is_empty() && !n.src_ip.trim().is_empty())
            .unwrap_or(false);
        if !has_remote {
            valid = false;
        }
    }
    if event.event_type == DnsQuery {
        let has_query = event
            .dns
            .as_ref()
            .map(|d| !d.query.trim().is_empty())
            .unwrap_or(false);
        if !has_query {
            valid = false;
        }
    }
    if !valid {
        event.tags.push("INVALID".to_string());
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn valid_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(osiris_schema::ProcessRef {
                process_key: osiris_schema::ProcessKey::new(host_id, "b", 1, 1),
                pid: 1,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
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
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn valid_event_gets_no_tag() {
        let mut event = valid_event();
        assert!(validate(&mut event));
        assert!(!event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn process_exec_without_process_ref_is_invalid_but_still_tagged_not_dropped() {
        let mut event = valid_event();
        event.process = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn nil_host_id_is_invalid() {
        let mut event = valid_event();
        event.host_id = Uuid::nil();
        assert!(!validate(&mut event));
    }

    fn valid_file_event(event_type: EventType) -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = event_type;
        event.category = Category::File;
        event.file = Some(osiris_schema::FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: if event_type == EventType::FileRename {
                Some("/var/www/html/.shell.php.tmp".to_string())
            } else {
                None
            },
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    #[test]
    fn well_formed_file_events_of_every_type_validate() {
        for event_type in [
            EventType::FileCreate,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::FileRename,
        ] {
            let mut event = valid_file_event(event_type);
            assert!(validate(&mut event), "{event_type:?} should be valid");
            assert!(!event.tags.contains(&"INVALID".to_string()));
        }
    }

    #[test]
    fn file_event_without_a_file_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_file_event(EventType::FileCreate);
        event.file = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn file_event_with_an_empty_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileWrite);
        if let Some(file) = event.file.as_mut() {
            file.path = "   ".to_string();
        }
        assert!(!validate(&mut event));
    }

    /// A FILE_RENAME with no `previous_path` carries no information about
    /// where the file moved from, which is the entire point of the type.
    #[test]
    fn file_rename_without_a_previous_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileRename);
        if let Some(file) = event.file.as_mut() {
            file.previous_path = None;
        }
        assert!(!validate(&mut event));
    }

    fn valid_network_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::NetworkConnect;
        event.category = Category::Network;
        event.process = None;
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 51000,
            dst_ip: "203.0.113.50".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    #[test]
    fn well_formed_network_events_of_every_type_validate() {
        for event_type in [
            EventType::NetworkConnect,
            EventType::NetworkAccept,
            EventType::NetworkClose,
        ] {
            let mut event = valid_network_event();
            event.event_type = event_type;
            assert!(validate(&mut event), "{event_type:?} should be valid");
        }
    }

    #[test]
    fn network_event_without_a_network_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_network_event();
        event.network = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn network_event_with_an_empty_remote_address_is_invalid() {
        let mut event = valid_network_event();
        if let Some(net) = event.network.as_mut() {
            net.dst_ip = "   ".to_string();
        }
        assert!(!validate(&mut event));
    }

    fn valid_dns_event() -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = EventType::DnsQuery;
        event.category = Category::Dns;
        event.process = None;
        event.dns = Some(osiris_schema::DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
        });
        event
    }

    #[test]
    fn well_formed_dns_query_validates() {
        let mut event = valid_dns_event();
        assert!(validate(&mut event));
    }

    #[test]
    fn dns_query_without_a_dns_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_dns_event();
        event.dns = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn dns_query_with_an_empty_query_string_is_invalid() {
        let mut event = valid_dns_event();
        if let Some(dns) = event.dns.as_mut() {
            dns.query = "".to_string();
        }
        assert!(!validate(&mut event));
    }

    /// An unresolved query (NXDOMAIN/timeout) is still a valid, storable
    /// event — empty `response_ips` is itself sometimes the signal, not a
    /// malformed record (Task 1's `DnsEventRaw` doc comment).
    #[test]
    fn dns_query_with_no_response_ips_is_still_valid() {
        let mut event = valid_dns_event();
        if let Some(dns) = event.dns.as_mut() {
            dns.response_ips = vec![];
        }
        assert!(validate(&mut event));
    }
}
