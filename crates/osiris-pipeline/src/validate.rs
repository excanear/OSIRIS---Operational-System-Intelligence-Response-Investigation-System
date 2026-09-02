use osiris_schema::CanonicalEvent;

/// Validate stage (ARCHITECTURE.md §7.1 step 4): a failing event is never
/// silently dropped — it is tagged INVALID and still forwarded, so an
/// operator can see what's malformed rather than have a silent gap.
/// Returns true if the event was valid (no tag added).
pub fn validate(event: &mut CanonicalEvent) -> bool {
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
            event_id: Uuid::now_v7(), schema_version: SCHEMA_VERSION.to_string(),
            host_id, boot_id: "b".to_string(), timestamp: 1, monotonic_timestamp: 1,
            event_type: EventType::ProcessExec, category: Category::Process, severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None,
            process: Some(osiris_schema::ProcessRef {
                process_key: osiris_schema::ProcessKey::new(host_id, "b", 1, 1),
                pid: 1, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 1,
            }),
            parent_process: None, thread: None, file: None, network: None, dns: None, device: None,
            service: None, container: None, namespace: None, cgroup: None, kernel: None,
            source: Source::Synthetic, provider: "test".to_string(), raw_event: None,
            relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
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
}
