use osiris_schema::{Alert, CanonicalEvent};
use osiris_storage::{AlertQueryPlan, Storage, StorageError};
use serde::Serialize;

/// The `{ events, alerts }` shape every `*_story` operation returns
/// (ARCHITECTURE.md §12.1). One shared type serializes identically to the
/// five distinct `FileStory`/`NetworkStory`/... structs `osiris-api` used
/// to define locally (plan Global Constraint #4: the JSON *shape* stays
/// unchanged, even though the Rust type backing it is now shared).
#[derive(Debug, Serialize)]
pub struct Story {
    pub events: Vec<CanonicalEvent>,
    pub alerts: Vec<Alert>,
}

/// Sorts `events` into a stable time order and attaches every `Alert`
/// whose evidence cites one of them — the composition step every
/// `*_story` operation shares (ARCHITECTURE.md §12.1: "assembled and
/// returned as a time-ordered structure").
pub fn assemble(
    storage: &dyn Storage,
    mut events: Vec<CanonicalEvent>,
) -> Result<Story, StorageError> {
    events.sort_by_key(|e| (e.timestamp, e.event_id));

    let evidence_ids: Vec<uuid::Uuid> = events.iter().map(|e| e.event_id).collect();
    let alerts = if evidence_ids.is_empty() {
        vec![]
    } else {
        let mut plan = AlertQueryPlan::new();
        plan.evidence_event_ids = evidence_ids;
        plan.limit = 10_000;
        storage.query_alerts(&plan)?
    };

    Ok(Story { events, alerts })
}

#[cfg(test)]
mod tests {
    use super::assemble;
    use osiris_schema::{
        CanonicalEvent, Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn sample_event(pid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
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
                process_key: ProcessKey::new(host_id, "b", pid, timestamp),
                pid,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
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
    fn assemble_sorts_events_by_timestamp_then_event_id() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let late = sample_event(2, 200);
        let early = sample_event(1, 100);
        let story = assemble(&storage, vec![late.clone(), early.clone()]).unwrap();
        assert_eq!(story.events[0].event_id, early.event_id);
        assert_eq!(story.events[1].event_id, late.event_id);
    }

    #[test]
    fn assemble_returns_no_alerts_for_an_empty_event_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let story = assemble(&storage, vec![]).unwrap();
        assert!(story.alerts.is_empty());
    }
}
