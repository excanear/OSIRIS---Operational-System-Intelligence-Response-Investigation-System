use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

/// ARCHITECTURE.md §12.1's Identity Story, refactored from `osiris-api`'s
/// former `identity_story_handler`. `session_id` alone already returns the
/// whole multi-category chain the Enrich stage attaches to every
/// descendant of a login; `uid` alone does NOT expand to every session
/// that user opened (deliberately — that fan-out needs the graph, not a
/// flat filter); both given intersects, expressed as one `AND` node so a
/// single `query_events` call does the intersection.
pub fn identity_story(
    storage: &dyn Storage,
    session_id: Option<&str>,
    uid: Option<u32>,
) -> Result<Story, StorageError> {
    let session_ast = session_id.map(|s| Ast::Compare {
        field: "session.session_id".to_string(),
        op: Op::Eq,
        value: Value::Str(s.to_string()),
    });
    let uid_ast = uid.map(|u| Ast::Compare {
        field: "user.uid".to_string(),
        op: Op::Eq,
        value: Value::Num(u as f64),
    });

    let filter = match (session_ast, uid_ast) {
        (Some(s), Some(u)) => Some(Ast::And(Box::new(s), Box::new(u))),
        (Some(s), None) => Some(s),
        (None, Some(u)) => Some(u),
        (None, None) => None,
    };

    let plan = EventQueryPlan {
        filter,
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
    use osiris_schema::{
        CanonicalEvent, Category, EventType, HostRef, SessionRef, Severity, Source, UserRef,
        SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn session_event(session_id: &str, uid: u32, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::SessionLogin,
            category: Category::Identity,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: Some(UserRef {
                uid,
                gid: uid,
                euid: uid,
                egid: uid,
                username: None,
                loginuid: Some(uid),
            }),
            session: Some(SessionRef {
                session_id: session_id.to_string(),
                tty: None,
                remote_addr: None,
                auth_method: None,
            }),
            process: None,
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
    fn identity_story_by_session_id_returns_the_whole_session() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&session_event("sess-1", 1000, 100)).unwrap();
        storage.write(&session_event("sess-2", 1000, 200)).unwrap();

        let story = identity_story(&storage, Some("sess-1"), None).unwrap();
        assert_eq!(story.events.len(), 1);
    }

    #[test]
    fn identity_story_by_uid_and_session_id_intersects_both() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&session_event("sess-1", 1000, 100)).unwrap();
        storage.write(&session_event("sess-1", 2000, 200)).unwrap();

        let story = identity_story(&storage, Some("sess-1"), Some(1000)).unwrap();
        assert_eq!(story.events.len(), 1);
        assert_eq!(story.events[0].user.as_ref().unwrap().uid, 1000);
    }
}
