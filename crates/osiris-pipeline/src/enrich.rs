use osiris_schema::CanonicalEvent;

use crate::process_resolver::ProcessResolver;

/// Enrich (local) stage (ARCHITECTURE.md §7.1 step 3): attach host/boot
/// identity and resolve parent_process via the Process Resolver. Cheap,
/// always-available context only — expensive enrichment is server-side
/// (Phase 1 does not implement server-side enrichment; §7.2's split is
/// preserved by simply not doing that work yet, not by doing it here).
pub fn enrich(
    mut event: CanonicalEvent,
    boot_id: &str,
    resolver: &mut ProcessResolver,
) -> CanonicalEvent {
    event.boot_id = boot_id.to_string();

    if let Some(process) = &event.process {
        let ppid = current_ppid(&event);
        resolver.record(process.pid, ppid, process.process_key);
        event.parent_process =
            resolver
                .resolve_parent(process.pid)
                .map(|parent_key| osiris_schema::ProcessRef {
                    process_key: parent_key,
                    // The real ppid (finding 5) — not the placeholder 0
                    // that was indistinguishable from a genuine pid 0
                    // once persisted and served over /api/v1/events.
                    pid: ppid,
                    // ProcessResolver's cache (by_pid) only stores
                    // (ProcessKey, ppid), not exe_path, so there is no
                    // cheap cached value to populate this from without
                    // adding a new lookup mechanism (out of scope for
                    // this fix) — leave it empty, an honest "unknown"
                    // rather than paired with a wrong pid.
                    exe_path: String::new(),
                    cmdline: vec![],
                    exe_hash: None,
                    start_time_mono: 0,
                });
    }
    event
}

fn current_ppid(event: &CanonicalEvent) -> u32 {
    event
        .event_data
        .get("ppid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn bare_event(host_id: uuid::Uuid, pid: u32, ppid: u32) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: String::new(),
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
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "boot-1", pid, 1),
                pid,
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
            event_data: serde_json::json!({ "ppid": ppid }),
        }
    }

    #[test]
    fn attaches_boot_id() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let event = enrich(bare_event(host_id, 100, 1), "boot-xyz", &mut resolver);
        assert_eq!(event.boot_id, "boot-xyz");
    }

    #[test]
    fn resolves_parent_process_when_parent_already_seen() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);
        assert_eq!(
            curl.parent_process.unwrap().process_key,
            bash.process.unwrap().process_key
        );
    }

    /// Regression test for finding 5: `parent_process.pid` must be the
    /// real ppid, not the placeholder `0` (which, once persisted and
    /// served over /api/v1/events, is indistinguishable from a genuine
    /// pid 0).
    #[test]
    fn parent_process_pid_is_the_real_ppid_not_a_placeholder_zero() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let _bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);

        let parent = curl.parent_process.expect("parent must resolve");
        assert_eq!(parent.pid, 100, "must be the real ppid, not 0");
    }
}
