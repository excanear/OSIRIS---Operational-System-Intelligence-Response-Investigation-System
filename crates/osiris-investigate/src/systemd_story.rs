use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Systemd Story, refactored from `osiris-api`'s
/// former `systemd_story_handler`. One `service.unit_name` filter spans
/// both the Systemd sensor's runtime lifecycle events and the Persistence
/// Monitor's unit-file lifecycle events, since Normalize populates the
/// field identically for both.
pub fn systemd_story(storage: &dyn Storage, unit_name: &str) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "service.unit_name".to_string(),
            op: Op::Eq,
            value: Value::Str(unit_name.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let events = storage.query_events(&plan)?;
    assemble(storage, events)
}

#[cfg(test)]
mod tests {
    use osiris_schema::{
        CanonicalEvent, Category, EventType, HostRef, ServiceRef, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage::Storage;
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn service_event(unit_name: &str, event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Systemd,
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
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: Some(ServiceRef {
                unit_name: unit_name.to_string(),
                unit_type: "service".to_string(),
                action: "start".to_string(),
            }),
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
    fn systemd_story_covers_both_lifecycle_and_unit_file_events_for_one_unit() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage
            .write(&service_event(
                "evil.service",
                EventType::ServiceCreate,
                100,
            ))
            .unwrap();
        storage
            .write(&service_event("evil.service", EventType::ServiceStart, 200))
            .unwrap();
        storage
            .write(&service_event(
                "other.service",
                EventType::ServiceStart,
                300,
            ))
            .unwrap();

        let story = super::systemd_story(&storage, "evil.service").unwrap();
        assert_eq!(story.events.len(), 2);
    }
}
