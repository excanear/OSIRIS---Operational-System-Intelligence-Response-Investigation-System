use std::collections::{HashMap, HashSet};

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, FileIdentity};
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

fn identity_filter_plan(identity: FileIdentity) -> EventQueryPlan {
    let ast = Ast::And(
        Box::new(Ast::Compare {
            field: "file.inode".to_string(),
            op: Op::Eq,
            value: Value::Num(identity.inode as f64),
        }),
        Box::new(Ast::Compare {
            field: "file.device_id".to_string(),
            op: Op::Eq,
            value: Value::Num(identity.device_id as f64),
        }),
    );
    EventQueryPlan {
        filter: Some(ast),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

fn path_filter_plan(path: &str) -> EventQueryPlan {
    EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "file.path".to_string(),
            op: Op::Eq,
            value: Value::Str(path.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

/// ARCHITECTURE.md §12.1's File Story, refactored from `osiris-api`'s
/// former `file_story_handler` into a reusable composition: `path`
/// resolves to every event carrying that literal path, plus (via the
/// `FileIdentity` those events carry) every event sharing the same
/// `(inode, device_id)` — the join that survives a `FILE_RENAME` — and
/// `file_id` looks an identity up directly, both routed through
/// `EventQueryPlan` (ARCHITECTURE.md §12.3) instead of the fixed-field
/// `osiris_storage::QueryPlan` the old handler used.
pub fn file_story(
    storage: &dyn Storage,
    path: Option<&str>,
    file_id: Option<FileIdentity>,
) -> Result<Story, StorageError> {
    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();
    let mut identities: HashSet<FileIdentity> = HashSet::new();

    if let Some(identity) = file_id {
        identities.insert(identity);
    }

    if let Some(path) = path {
        let path_events = storage.query_events(&path_filter_plan(path))?;
        for e in &path_events {
            if let Some(file) = &e.file {
                if let Some(id) = FileIdentity::from_file_ref(file) {
                    identities.insert(id);
                }
            }
        }
        for e in path_events {
            events_by_id.insert(e.event_id, e);
        }
    }

    for identity in &identities {
        for e in storage.query_events(&identity_filter_plan(*identity))? {
            events_by_id.insert(e.event_id, e);
        }
    }

    assemble(storage, events_by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, FileRef, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn file_event(
        event_type: EventType,
        path: &str,
        inode: u64,
        device_id: u64,
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
            event_type,
            category: Category::File,
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
            file: Some(FileRef {
                path: path.to_string(),
                previous_path: None,
                inode: Some(inode),
                device_id: Some(device_id),
                size: None,
                mode: None,
                owner_uid: None,
                owner_gid: None,
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
    fn file_story_by_path_follows_a_rename_via_inode_and_device_id() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage
            .write(&file_event(
                EventType::FileCreate,
                "/tmp/a.txt",
                111,
                1,
                100,
            ))
            .unwrap();
        storage
            .write(&file_event(
                EventType::FileRename,
                "/tmp/b.txt",
                111,
                1,
                200,
            ))
            .unwrap();

        let story = file_story(&storage, Some("/tmp/a.txt"), None).unwrap();
        assert_eq!(
            story.events.len(),
            2,
            "both the original and renamed-to path must appear"
        );
        assert_eq!(story.events[0].timestamp, 100);
        assert_eq!(story.events[1].timestamp, 200);
    }

    #[test]
    fn file_story_by_file_id_looks_up_identity_directly() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage
            .write(&file_event(
                EventType::FileCreate,
                "/tmp/a.txt",
                222,
                1,
                100,
            ))
            .unwrap();
        let identity = osiris_schema::FileIdentity::new(222, 1);

        let story = file_story(&storage, None, Some(identity)).unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[test]
    fn file_story_with_no_matches_returns_an_empty_story() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let story = file_story(&storage, Some("/nowhere"), None).unwrap();
        assert!(story.events.is_empty());
        assert!(story.alerts.is_empty());
    }
}
