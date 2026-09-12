use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};
use uuid::Uuid;

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's System Story (new in this phase):
/// `system_story(host_id, time_range) -> SystemStory` — every event on one
/// host within one time range, the whole-host Timeline an investigation
/// starts from before narrowing to a specific process/file/session.
pub fn system_story(storage: &dyn Storage, host_id: Uuid, since: u64, until: u64) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "host_id".to_string(),
            op: Op::Eq,
            value: Value::Str(host_id.to_string()),
        }),
        since: Some(since),
        until: Some(until),
        limit: 10_000,
        export: true,
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{CanonicalEvent, Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage::Storage;
    use osiris_storage_sqlite::SqliteStorage;

    fn host_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
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
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None, container: None, namespace: None,
            cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn system_story_returns_only_this_hosts_events_within_the_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_a = Uuid::new_v4();
        let host_b = Uuid::new_v4();
        storage.write(&host_event(host_a, 100)).unwrap();
        storage.write(&host_event(host_a, 500)).unwrap();
        storage.write(&host_event(host_a, 900)).unwrap();
        storage.write(&host_event(host_b, 500)).unwrap();

        let story = system_story(&storage, host_a, 200, 600).unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].timestamp, 500);
    }
}
