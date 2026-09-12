use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Container Story, refactored from `osiris-api`'s
/// former `container_story_handler`. One `container.container_id` filter
/// spans both the Container sensor's own lifecycle events and every other
/// category's events enriched with that container's id by
/// `NsCgroupResolver`.
pub fn container_story(storage: &dyn Storage, container_id: &str) -> Result<Story, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "container.container_id".to_string(),
            op: Op::Eq,
            value: Value::Str(container_id.to_string()),
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
    use super::*;
    use osiris_schema::{CanonicalEvent, Category, ContainerRef, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn container_event(container_id: &str, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ContainerStart,
            category: Category::Container,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None,
            container: Some(ContainerRef { container_id: container_id.to_string(), image: "img".to_string(), runtime: "docker".to_string(), pod_ref: None }),
            namespace: None, cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn container_story_returns_only_that_containers_events() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&container_event("c1", 100)).unwrap();
        storage.write(&container_event("c2", 200)).unwrap();

        let story = container_story(&storage, "c1").unwrap();
        assert_eq!(story.events.len(), 1);
    }
}
