use std::collections::HashMap;

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, ProcessKey};
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Process Story (new in this phase). Two
/// `EventQueryPlan` queries: every event where this process is the acting
/// `process` (covers exec/exit and every `WROTE`/`READ`/`CONNECTED_TO`/
/// `EXECUTED_AS` category event, since Normalize always attaches the acting
/// process the same way `session_id`/`unit_name`/`container_id` are
/// attached in earlier phases), plus every event where this process is the
/// `parent_process` (its direct children's own exec events — one level of
/// descendant lineage). Full n-level ancestor/descendant graph walking is
/// what `reconstruct_incident` and the Entity Graph v2 subgraph (both
/// later in this Part) provide instead of duplicating a graph walk here.
pub fn process_story(
    storage: &dyn Storage,
    process_key: ProcessKey,
) -> Result<Story, StorageError> {
    let own_plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };
    let children_plan = EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "parent_process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    };

    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
    for e in storage.query_events(&own_plan)? {
        events_by_id.insert(e.event_id, e);
    }
    for e in storage.query_events(&children_plan)? {
        events_by_id.insert(e.event_id, e);
    }

    assemble(storage, events_by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, FileRef, HostRef, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn exec_event(
        process_key: ProcessKey,
        parent_key: Option<ProcessKey>,
        pid: u32,
        timestamp: u64,
    ) -> CanonicalEvent {
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
                process_key,
                pid,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: timestamp,
            }),
            parent_process: parent_key.map(|k| ProcessRef {
                process_key: k,
                pid: 0,
                exe_path: String::new(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 0,
            }),
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

    fn write_event(process_key: ProcessKey, path: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = exec_event(process_key, None, 1, timestamp);
        e.event_type = EventType::FileWrite;
        e.category = Category::File;
        e.file = Some(FileRef {
            path: path.to_string(),
            previous_path: None,
            inode: None,
            device_id: None,
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        e
    }

    #[test]
    fn process_story_includes_the_processs_own_activity_and_its_direct_children() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_id = Uuid::new_v4();
        let parent_key = ProcessKey::new(host_id, "b", 10, 100);
        let child_key = ProcessKey::new(host_id, "b", 20, 200);

        storage
            .write(&exec_event(parent_key, None, 10, 100))
            .unwrap();
        storage
            .write(&write_event(parent_key, "/etc/passwd", 150))
            .unwrap();
        storage
            .write(&exec_event(child_key, Some(parent_key), 20, 200))
            .unwrap();
        storage
            .write(&exec_event(
                ProcessKey::new(host_id, "b", 99, 999),
                None,
                99,
                999,
            ))
            .unwrap();

        let story = process_story(&storage, parent_key).unwrap();
        assert_eq!(
            story.events.len(),
            3,
            "own exec, own file write, and the direct child's exec"
        );
    }
}
