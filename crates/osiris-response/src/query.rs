use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, EntityRef};
use osiris_storage::{Storage, StorageError};

/// Builds the OQL comparison that matches every event touching `entity`,
/// mirroring the field-per-kind approach `osiris-investigate`'s
/// `network_story`/`process_story` already use (ARCHITECTURE.md §12.1) —
/// one query primitive reused across every `EntityRef` kind rather than a
/// new one invented for the Response Engine.
pub(crate) fn entity_query_ast(entity: &EntityRef) -> Ast {
    match entity {
        EntityRef::Process { process_key } => Ast::Compare {
            field: "process.process_key".to_string(),
            op: Op::Eq,
            value: Value::Str(process_key.as_hex()),
        },
        EntityRef::File {
            host_id,
            inode,
            device_id,
        } => Ast::And(
            Box::new(Ast::And(
                Box::new(Ast::Compare {
                    field: "file.inode".to_string(),
                    op: Op::Eq,
                    value: Value::Num(*inode as f64),
                }),
                Box::new(Ast::Compare {
                    field: "file.device_id".to_string(),
                    op: Op::Eq,
                    value: Value::Num(*device_id as f64),
                }),
            )),
            Box::new(Ast::Compare {
                field: "host_id".to_string(),
                op: Op::Eq,
                value: Value::Str(host_id.to_string()),
            }),
        ),
        EntityRef::Ip { addr } => Ast::Or(
            Box::new(Ast::Compare {
                field: "network.src_ip".to_string(),
                op: Op::Eq,
                value: Value::Str(addr.clone()),
            }),
            Box::new(Ast::Compare {
                field: "network.dst_ip".to_string(),
                op: Op::Eq,
                value: Value::Str(addr.clone()),
            }),
        ),
        EntityRef::Domain { name } => Ast::Compare {
            field: "dns.query".to_string(),
            op: Op::Eq,
            value: Value::Str(name.clone()),
        },
        EntityRef::User { host_id, uid } => Ast::And(
            Box::new(Ast::Compare {
                field: "user.uid".to_string(),
                op: Op::Eq,
                value: Value::Num(*uid as f64),
            }),
            Box::new(Ast::Compare {
                field: "host_id".to_string(),
                op: Op::Eq,
                value: Value::Str(host_id.to_string()),
            }),
        ),
        EntityRef::Container { container_id } => Ast::Compare {
            field: "container.container_id".to_string(),
            op: Op::Eq,
            value: Value::Str(container_id.clone()),
        },
        EntityRef::Session { session_id } => Ast::Compare {
            field: "session.session_id".to_string(),
            op: Op::Eq,
            value: Value::Str(session_id.clone()),
        },
    }
}

/// Every event touching `entity` within `[since, until]`, bounded by
/// `limit` (clamped further to `osiris_query::MAX_EVENT_LIMIT` when
/// `export` is true — see `EventQueryPlan::effective_limit`).
pub fn events_for_entity(
    storage: &dyn Storage,
    entity: &EntityRef,
    since: u64,
    until: u64,
    limit: usize,
    export: bool,
) -> Result<Vec<CanonicalEvent>, StorageError> {
    let plan = EventQueryPlan {
        filter: Some(entity_query_ast(entity)),
        since: Some(since),
        until: Some(until),
        limit,
        export,
        host_ids: None,
    };
    storage.query_events(&plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, ContainerRef, DnsRef, EventType, FileRef, HostRef, NetworkDirection, NetworkRef,
        ProcessKey, ProcessRef, SessionRef, Severity, Source, UserRef, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
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
    fn entity_query_ast_matches_a_process_event_by_process_key() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef {
            process_key,
            pid: 42,
            exe_path: "/bin/x".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 1000,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Process { process_key },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event_id, e.event_id);
    }

    #[test]
    fn entity_query_ast_matches_a_file_event_by_inode_and_device_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::FileWrite;
        e.category = Category::File;
        e.file = Some(FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(9),
            device_id: Some(1),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        storage.write(&e).unwrap();

        // Same inode/device_id, different host — must NOT match (Fix 5:
        // host_id was previously dropped from the query, so this event's
        // presence would falsely widen the match to every host).
        let other_host_id = Uuid::new_v4();
        let mut other_host_event = base_event(other_host_id, 1000);
        other_host_event.event_type = EventType::FileWrite;
        other_host_event.category = Category::File;
        other_host_event.file = Some(FileRef {
            path: "/tmp/other-host-shell.php".to_string(),
            previous_path: None,
            inode: Some(9),
            device_id: Some(1),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        storage.write(&other_host_event).unwrap();

        let target = EntityRef::File {
            host_id,
            inode: 9,
            device_id: 1,
        };
        let found = events_for_entity(&storage, &target, 0, u64::MAX, 10, false).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event_id, e.event_id);

        let miss = EntityRef::File {
            host_id,
            inode: 999,
            device_id: 1,
        };
        assert!(events_for_entity(&storage, &miss, 0, u64::MAX, 10, false)
            .unwrap()
            .is_empty());

        let other_host_target = EntityRef::File {
            host_id: other_host_id,
            inode: 9,
            device_id: 1,
        };
        let found_other =
            events_for_entity(&storage, &other_host_target, 0, u64::MAX, 10, false).unwrap();
        assert_eq!(found_other.len(), 1);
        assert_eq!(found_other[0].event_id, other_host_event.event_id);
    }

    #[test]
    fn entity_query_ast_matches_an_ip_event_on_either_side_of_the_connection() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::NetworkConnect;
        e.category = Category::Network;
        e.network = Some(NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 5555,
            dst_ip: "203.0.113.10".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes: None,
        });
        storage.write(&e).unwrap();

        let by_dst = events_for_entity(
            &storage,
            &EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(by_dst.len(), 1);
        let by_src = events_for_entity(
            &storage,
            &EntityRef::Ip {
                addr: "10.0.0.5".to_string(),
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(by_src.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_domain_event_by_dns_query() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        e.dns = Some(DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Domain {
                name: "cdn-assets.xyz".to_string(),
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_user_event_by_uid() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::SessionLogin;
        e.category = Category::Identity;
        e.user = Some(UserRef {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            username: Some("root".to_string()),
            loginuid: Some(0),
        });
        storage.write(&e).unwrap();

        // Same uid, different host — must NOT match (Fix 5, see the File
        // test's comment above for why this matters).
        let other_host_id = Uuid::new_v4();
        let mut other_host_event = base_event(other_host_id, 1000);
        other_host_event.event_type = EventType::SessionLogin;
        other_host_event.category = Category::Identity;
        other_host_event.user = Some(UserRef {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            username: Some("root".to_string()),
            loginuid: Some(0),
        });
        storage.write(&other_host_event).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::User { host_id, uid: 0 },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event_id, e.event_id);

        let found_other = events_for_entity(
            &storage,
            &EntityRef::User {
                host_id: other_host_id,
                uid: 0,
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found_other.len(), 1);
        assert_eq!(found_other[0].event_id, other_host_event.event_id);
    }

    #[test]
    fn entity_query_ast_matches_a_container_event_by_container_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::ContainerStart;
        e.category = Category::Container;
        e.container = Some(ContainerRef {
            container_id: "abc123".to_string(),
            image: "nginx".to_string(),
            runtime: "docker".to_string(),
            pod_ref: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Container {
                container_id: "abc123".to_string(),
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn entity_query_ast_matches_a_session_event_by_session_id() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 1000);
        e.session = Some(SessionRef {
            session_id: "3".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        storage.write(&e).unwrap();

        let found = events_for_entity(
            &storage,
            &EntityRef::Session {
                session_id: "3".to_string(),
            },
            0,
            u64::MAX,
            10,
            false,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn events_for_entity_respects_the_since_until_window() {
        let host_id = Uuid::new_v4();
        let storage = SqliteStorage::open(tempfile::NamedTempFile::new().unwrap().path()).unwrap();
        let mut e = base_event(host_id, 5000);
        e.dns = Some(DnsRef {
            query: "x.example".to_string(),
            qtype: "A".to_string(),
            response_ips: vec![],
            ttl: None,
        });
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        storage.write(&e).unwrap();

        let target = EntityRef::Domain {
            name: "x.example".to_string(),
        };
        assert_eq!(
            events_for_entity(&storage, &target, 0, 4000, 10, false)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            events_for_entity(&storage, &target, 0, u64::MAX, 10, false)
                .unwrap()
                .len(),
            1
        );
    }
}
