use osiris_schema::{
    CanonicalEvent, Category, EntityRef, EntityRelationship, EventType, FileIdentity, ProcessRef,
    Relation, SessionRef,
};

use crate::process_resolver::ProcessResolver;
use crate::session_resolver::{SessionRecord, SessionResolver};

/// Enrich (local) stage (ARCHITECTURE.md §7.1 step 3): attach host/boot
/// identity, resolve process identity via the Process Resolver, attach
/// session identity via the Session Resolver (§26 step 3), and compute the
/// entity-graph edges §9.4 requires be written once here rather than
/// re-derived by every consumer. Cheap, always-available context only —
/// expensive enrichment is server-side (§7.2's split is preserved by simply
/// not doing that work yet, not by doing it here).
pub fn enrich(
    mut event: CanonicalEvent,
    boot_id: &str,
    resolver: &mut ProcessResolver,
    sessions: &mut SessionResolver,
) -> CanonicalEvent {
    event.boot_id = boot_id.to_string();

    match event.category {
        // Process events are the *source* of process identity: Normalize
        // hashed the real start time into their process_key, and they
        // populate the resolver for everyone else.
        Category::Process => enrich_process_event(&mut event, resolver),
        // Every other category *consumes* identity: the pid is known but
        // the start time isn't, so Normalize could only mint a provisional
        // key. Replace it with the authoritative one where we have it.
        _ => enrich_non_process_event(&mut event, resolver),
    }

    attach_session(&mut event, sessions);

    match event.category {
        Category::File => attach_file_relationship(&mut event),
        Category::Network => attach_network_relationship(&mut event),
        Category::Dns => attach_dns_relationships(&mut event),
        Category::Process => attach_session_relationship(&mut event),
        Category::Privilege => attach_executed_as_relationship(&mut event),
        _ => {}
    }

    event
}

/// §26 step 3's session linkage, in both directions:
///
/// * An IDENTITY event is the *source* of session identity — Normalize
///   already populated its `session`/`user` from the record itself, so here
///   it only teaches (or un-teaches) the resolver.
/// * Every other event *consumes* it: its pid, or its parent's pid, may
///   belong to a known session, in which case the full `SessionRef` is
///   attached. When neither does, `session` is left exactly as Normalize
///   produced it — `None` for most categories, and the minimal
///   `ses=`-derived ref for privilege events (plan Global Constraint #5:
///   never a guessed session id).
fn attach_session(event: &mut CanonicalEvent, sessions: &mut SessionResolver) {
    if event.category == Category::Identity {
        let (Some(session), Some(process)) = (event.session.clone(), event.process.as_ref())
        else {
            return;
        };
        match event.event_type {
            EventType::SessionLogin | EventType::SessionCreate => {
                sessions.record_login(
                    process.pid,
                    SessionRecord {
                        session_id: session.session_id.clone(),
                        uid: event.user.as_ref().map(|u| u.uid).unwrap_or(0),
                        username: event.user.as_ref().and_then(|u| u.username.clone()),
                        tty: session.tty.clone(),
                        remote_addr: session.remote_addr.clone(),
                        auth_method: session.auth_method.clone(),
                    },
                );
            }
            EventType::SessionLogout | EventType::SessionTerminate => {
                sessions.forget(&session.session_id);
            }
            _ => {}
        }
        return;
    }

    let Some(pid) = event.process.as_ref().map(|p| p.pid) else {
        return;
    };
    let ppid = current_ppid(event);
    let inferred_session_id = sessions.attach(pid, ppid);

    // An event may already carry an observed session id, populated
    // directly from the record's own `ses=` field in Normalize
    // (`normalize_privilege_event` does this today; this phase's
    // `normalize_systemd_event` will too). Observation always wins over
    // pid/ppid inference here — the same "never let a guess override a
    // fact" discipline this stage already applies to process identity
    // (`PROCESS_KEY_PROVISIONAL`) and file identity (no edge over a
    // fabricated one). `sessions.attach` above is still called
    // unconditionally for its pid-inheritance teaching side effect —
    // unrelated descendants of `pid` must still resolve correctly through
    // it — only its *return value* is demoted to a fallback here.
    let session_id = match event.session.as_ref() {
        Some(observed) => observed.session_id.clone(),
        None => match inferred_session_id {
            Some(inferred) => inferred,
            None => return,
        },
    };

    let Some(record) = sessions.record_for(&session_id) else {
        // The session id (observed or inferred) doesn't match a known
        // login record. Leave `event.session` exactly as Normalize
        // produced it — a minimal ref, or `None` — rather than discarding
        // real, directly-observed data because enrichment has nothing
        // fuller to offer it.
        return;
    };
    event.session = Some(SessionRef {
        session_id: record.session_id.clone(),
        tty: record.tty.clone(),
        remote_addr: record.remote_addr.clone(),
        auth_method: record.auth_method.clone(),
    });
}

/// Writes the §9.4 `Process -TRIGGERED_BY_SESSION-> Session` edge (plan
/// Global Constraint #8). Only on `PROCESS_EXEC`: every later event from
/// that process carries the same session, so repeating the edge on each of
/// them would write one fact hundreds of times per session — the same
/// duplicate-fact reasoning that keeps `CONNECTED_TO` off `NETWORK_CLOSE`.
fn attach_session_relationship(event: &mut CanonicalEvent) {
    if event.event_type != EventType::ProcessExec {
        return;
    }
    let (Some(process), Some(session)) = (event.process.as_ref(), event.session.as_ref()) else {
        return;
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::Session {
            session_id: session.session_id.clone(),
        },
        relation: Relation::TriggeredBySession,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

/// Writes the §9.4 `Process -EXECUTED_AS-> User` edge (plan Global
/// Constraint #8). Attached on `PRIVILEGE_UID_CHANGE` only, and even then
/// only for a real uid transition: a target uid that is present *and
/// different from* the acting uid. Explicitly never attached on
/// `PRIVILEGE_GID_CHANGE` (`EntityRef::User` is keyed by uid; there is no
/// group entity, and encoding a gid there would corrupt the graph) or on
/// `PRIVILEGE_SUDO` — auditd's `USER_CMD` record does not reliably carry
/// the target account across distributions (plan Global Constraint #8),
/// so even a populated `target_uid` on a sudo event must not mint an edge.
fn attach_executed_as_relationship(event: &mut CanonicalEvent) {
    if event.event_type != EventType::PrivilegeUidChange {
        return;
    }
    let Some(process) = event.process.as_ref() else {
        return;
    };
    let Some(target_uid) = event
        .event_data
        .get("target_uid")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
    else {
        return;
    };
    if event.user.as_ref().map(|u| u.uid) == Some(target_uid) {
        return;
    }
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::User {
            host_id: event.host_id,
            uid: target_uid,
        },
        relation: Relation::ExecutedAs,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

fn enrich_process_event(event: &mut CanonicalEvent, resolver: &mut ProcessResolver) {
    let Some(process) = &event.process else {
        return;
    };
    let (pid, process_key) = (process.pid, process.process_key);
    let ppid = current_ppid(event);
    resolver.record(pid, ppid, process_key);
    event.parent_process = resolver.resolve_parent(pid).map(|parent_key| ProcessRef {
        process_key: parent_key,
        // The real ppid (Phase 1 finding 5) — not the placeholder 0 that was
        // indistinguishable from a genuine pid 0 once persisted and served
        // over /api/v1/events.
        pid: ppid,
        // ProcessResolver's cache only stores (ProcessKey, ppid), not
        // exe_path, so there is no cheap cached value to populate this
        // from — leave it empty, an honest "unknown" rather than paired
        // with a wrong pid.
        exe_path: String::new(),
        cmdline: vec![],
        exe_hash: None,
        start_time_mono: 0,
    });
}

fn enrich_non_process_event(event: &mut CanonicalEvent, resolver: &ProcessResolver) {
    let Some(pid) = event.process.as_ref().map(|p| p.pid) else {
        return;
    };
    match resolver.resolve(pid) {
        Some(authoritative) => {
            if let Some(process) = event.process.as_mut() {
                process.process_key = authoritative;
            }
        }
        // The process exec'd before the Agent started, or its sensor is
        // disabled. The provisional key stays, but it is tagged so nothing
        // downstream mistakes it for a real, joinable process identity.
        None => event.tags.push("PROCESS_KEY_PROVISIONAL".to_string()),
    }
    event.parent_process = resolver
        .parent_of(pid)
        .map(|(parent_key, parent_pid)| ProcessRef {
            process_key: parent_key,
            pid: parent_pid,
            exe_path: String::new(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
}

/// Writes the §9.4 `Process -WROTE-> File` edge. `WROTE` covers create,
/// write, delete and rename alike: §9.4's relation set has no
/// DELETED/RENAMED member and this phase does not extend it — the precise
/// operation is always recoverable from the cited event's `event_type`
/// (Phase 2 plan Global Constraints #14). No edge is written when the
/// backend could not report a full file identity: an edge citing a
/// fabricated identity is worse than no edge at all.
fn attach_file_relationship(event: &mut CanonicalEvent) {
    let (Some(process), Some(file)) = (event.process.as_ref(), event.file.as_ref()) else {
        return;
    };
    let Some(identity) = FileIdentity::from_file_ref(file) else {
        return;
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: identity.to_entity_ref(event.host_id),
        relation: Relation::Wrote,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

/// Writes the §9.4 `Process -CONNECTED_TO-> Ip` edge (Phase 3 plan Global
/// Constraints #8). Only on the connection's *opening* event
/// (`NETWORK_CONNECT`/`NETWORK_ACCEPT`) — `NETWORK_CLOSE` would duplicate
/// the same fact. No edge when the sensor could not attribute a process
/// (Global Constraint #5) — an edge citing a fabricated process is worse
/// than no edge, the same reasoning `attach_file_relationship` already
/// applies to file identity.
fn attach_network_relationship(event: &mut CanonicalEvent) {
    if event.event_type == EventType::NetworkClose {
        return;
    }
    let (Some(process), Some(network)) = (event.process.as_ref(), event.network.as_ref()) else {
        return;
    };
    let remote_ip = match network.direction {
        osiris_schema::NetworkDirection::Outbound => &network.dst_ip,
        osiris_schema::NetworkDirection::Inbound => &network.src_ip,
    };
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: process.process_key,
        },
        to: EntityRef::Ip {
            addr: remote_ip.clone(),
        },
        relation: Relation::ConnectedTo,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    event.relationships.push(edge);
}

/// Writes one §9.4 `Domain -RESOLVED_TO-> Ip` edge per resolved address
/// (Phase 3 plan Global Constraints #8) — a query resolving to three IPs
/// produces three edges, all citing the same `event_id`. No
/// `Process -> Domain` edge: the frozen `Relation` enum has no fitting
/// variant, and this phase does not extend it (Phase 2 precedent: solve it
/// in the consuming crate or defer, never widen a frozen schema type for
/// one call site).
fn attach_dns_relationships(event: &mut CanonicalEvent) {
    let Some(dns) = event.dns.clone() else {
        return;
    };
    for ip in &dns.response_ips {
        let edge = EntityRelationship {
            from: EntityRef::Domain {
                name: dns.query.clone(),
            },
            to: EntityRef::Ip { addr: ip.clone() },
            relation: Relation::ResolvedTo,
            event_id: event.event_id,
            timestamp: event.timestamp,
        };
        event.relationships.push(edge);
    }
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
        Category, EventType, HostRef, ProcessKey, ProcessRef, Relation, Severity, Source,
        SCHEMA_VERSION,
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
        let mut sessions = SessionResolver::new();
        let event = enrich(bare_event(host_id, 100, 1), "boot-xyz", &mut resolver, &mut sessions);
        assert_eq!(event.boot_id, "boot-xyz");
    }

    #[test]
    fn resolves_parent_process_when_parent_already_seen() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver, &mut sessions);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
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
        let mut sessions = SessionResolver::new();
        let _bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver, &mut sessions);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        let parent = curl.parent_process.expect("parent must resolve");
        assert_eq!(parent.pid, 100, "must be the real ppid, not 0");
    }

    fn bare_file_event(host_id: uuid::Uuid, pid: u32, ppid: u32, inode: u64) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, ppid);
        event.event_type = EventType::FileWrite;
        event.category = Category::File;
        event.process = Some(ProcessRef {
            // The provisional key the Normalize stage mints for file events.
            process_key: ProcessKey::new(host_id, "boot-1", pid, 0),
            pid,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.file = Some(osiris_schema::FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(inode),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    #[test]
    fn file_event_adopts_the_authoritative_process_key_from_the_exec_event() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert_eq!(
            file_event.process.unwrap().process_key,
            authoritative,
            "a file event's process must be the same entity as its exec event"
        );
        assert!(!file_event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    #[test]
    fn file_event_for_an_unseen_pid_is_tagged_provisional_rather_than_guessing() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let file_event = enrich(
            bare_file_event(host_id, 777, 1, 131075),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert!(file_event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    #[test]
    fn file_event_resolves_its_parent_process_from_the_resolver() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        let _curl = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        let parent = file_event.parent_process.expect("parent must resolve");
        assert_eq!(parent.process_key, bash.process.unwrap().process_key);
        assert_eq!(parent.pid, 200);
    }

    /// ARCHITECTURE.md §9.4: relationships are computed once, at enrichment
    /// time, and stored as first-class edges — and the edge must cite the
    /// *authoritative* process key, which only exists after the lookup above.
    #[test]
    fn file_event_gains_a_process_wrote_file_entity_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert_eq!(file_event.relationships.len(), 1);
        let edge = &file_event.relationships[0];
        assert_eq!(edge.relation, Relation::Wrote);
        assert_eq!(edge.event_id, file_event.event_id);
        match (&edge.from, &edge.to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::File {
                    host_id: edge_host,
                    inode,
                    device_id,
                },
            ) => {
                assert_eq!(*process_key, authoritative);
                assert_eq!(*edge_host, host_id);
                assert_eq!(*inode, 131075);
                assert_eq!(*device_id, osiris_schema::encode_device_id(8, 1));
            }
            other => panic!("expected a Process -> File edge, got {other:?}"),
        }
    }

    #[test]
    fn file_event_without_a_usable_identity_gets_no_edge_rather_than_a_fabricated_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let mut event = bare_file_event(host_id, 300, 200, 131075);
        if let Some(file) = event.file.as_mut() {
            file.inode = None;
        }
        let enriched = enrich(event, "boot-1", &mut resolver, &mut sessions);
        assert!(enriched.relationships.is_empty());
    }

    /// Regression guard: the Process branch's behaviour (record, then
    /// resolve the parent by the ppid carried in event_data) must be
    /// untouched by the new non-process path.
    #[test]
    fn process_events_still_record_and_resolve_exactly_as_before() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver, &mut sessions);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        assert_eq!(
            curl.parent_process.unwrap().process_key,
            bash.process.unwrap().process_key
        );
    }

    fn bare_network_event(
        host_id: uuid::Uuid,
        pid: Option<u32>,
        remote_ip: &str,
    ) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid.unwrap_or(0), 0);
        event.event_type = EventType::NetworkConnect;
        event.category = Category::Network;
        event.process = pid.map(|p| ProcessRef {
            process_key: ProcessKey::new(host_id, "boot-1", p, 0),
            pid: p,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.network = Some(osiris_schema::NetworkRef {
            src_ip: "10.0.0.5".to_string(),
            src_port: 51000,
            dst_ip: remote_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: osiris_schema::NetworkDirection::Outbound,
            bytes: None,
        });
        event
    }

    #[test]
    fn network_event_gains_a_process_connected_to_ip_entity_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let authoritative = curl_exec.process.unwrap().process_key;

        let net_event = enrich(
            bare_network_event(host_id, Some(300), "203.0.113.50"),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert_eq!(net_event.relationships.len(), 1);
        let edge = &net_event.relationships[0];
        assert_eq!(edge.relation, Relation::ConnectedTo);
        match (&edge.from, &edge.to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::Ip { addr },
            ) => {
                assert_eq!(*process_key, authoritative);
                assert_eq!(addr, "203.0.113.50");
            }
            other => panic!("expected a Process -> Ip edge, got {other:?}"),
        }
    }

    #[test]
    fn network_event_with_no_pid_gets_no_edge_rather_than_a_fabricated_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let net_event = enrich(
            bare_network_event(host_id, None, "203.0.113.50"),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert!(net_event.relationships.is_empty());
        assert!(net_event.process.is_none());
    }

    #[test]
    fn network_close_event_gets_no_connected_to_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let mut event = bare_network_event(host_id, Some(300), "203.0.113.50");
        event.event_type = EventType::NetworkClose;
        let closed = enrich(event, "boot-1", &mut resolver, &mut sessions);
        assert!(
            closed.relationships.is_empty(),
            "the opening event already carries the edge; close must not duplicate it"
        );
    }

    fn bare_dns_event(host_id: uuid::Uuid, pid: Option<u32>, response_ips: Vec<String>) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid.unwrap_or(0), 0);
        event.event_type = EventType::DnsQuery;
        event.category = Category::Dns;
        event.process = pid.map(|p| ProcessRef {
            process_key: ProcessKey::new(host_id, "boot-1", p, 0),
            pid: p,
            exe_path: "/usr/bin/curl".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 0,
        });
        event.dns = Some(osiris_schema::DnsRef {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips,
            ttl: Some(300),
        });
        event
    }

    #[test]
    fn dns_event_gains_one_resolved_to_edge_per_response_ip() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let dns_event = enrich(
            bare_dns_event(
                host_id,
                Some(300),
                vec!["203.0.113.50".to_string(), "203.0.113.51".to_string()],
            ),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert_eq!(dns_event.relationships.len(), 2);
        for (edge, expected_ip) in dns_event
            .relationships
            .iter()
            .zip(["203.0.113.50", "203.0.113.51"])
        {
            assert_eq!(edge.relation, Relation::ResolvedTo);
            match (&edge.from, &edge.to) {
                (
                    osiris_schema::EntityRef::Domain { name },
                    osiris_schema::EntityRef::Ip { addr },
                ) => {
                    assert_eq!(name, "cdn-assets.xyz");
                    assert_eq!(addr, expected_ip);
                }
                other => panic!("expected a Domain -> Ip edge, got {other:?}"),
            }
        }
    }

    #[test]
    fn dns_event_with_no_response_ips_gets_no_edges() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec![]),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert!(dns_event.relationships.is_empty());
    }

    /// DNS's process resolution reuses the exact same non-process path
    /// file/network events already exercise — this pins that reuse rather
    /// than re-deriving a parallel code path.
    #[test]
    fn dns_event_resolves_its_authoritative_process_key() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let authoritative = curl_exec.process.unwrap().process_key;

        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec!["203.0.113.50".to_string()]),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert_eq!(dns_event.process.unwrap().process_key, authoritative);
        assert!(!dns_event.tags.contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    use crate::session_resolver::SessionResolver;
    use osiris_schema::{SessionRef, UserRef};

    fn login_event(host_id: uuid::Uuid, pid: u32) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, 1);
        event.event_type = EventType::SessionLogin;
        event.category = Category::Identity;
        event.session = Some(SessionRef {
            session_id: "3".to_string(),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
        });
        event.user = Some(UserRef {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            username: Some("alice".to_string()),
            loginuid: Some(1000),
        });
        event
    }

    fn privilege_event(
        host_id: uuid::Uuid,
        pid: u32,
        ppid: u32,
        acting_uid: u32,
        target_uid: Option<u32>,
    ) -> CanonicalEvent {
        let mut event = bare_event(host_id, pid, ppid);
        event.event_type = EventType::PrivilegeUidChange;
        event.category = Category::Privilege;
        event.user = Some(UserRef {
            uid: acting_uid,
            gid: acting_uid,
            euid: acting_uid,
            egid: acting_uid,
            username: None,
            loginuid: Some(1000),
        });
        event.event_data = serde_json::json!({ "ppid": ppid, "target_uid": target_uid });
        event
    }

    #[test]
    fn a_process_execed_inside_a_session_inherits_that_session() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        let _sshd = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver, &mut sessions);
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        let curl = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);

        for (name, event) in [("bash", &bash), ("curl", &curl)] {
            let session = event
                .session
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must inherit the SSH session"));
            assert_eq!(session.session_id, "3");
            assert_eq!(session.remote_addr.as_deref(), Some("198.51.100.10"));
            assert_eq!(session.auth_method.as_deref(), Some("sshd"));
        }
    }

    #[test]
    fn a_process_outside_any_session_gets_no_session_rather_than_a_guess() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let cron = enrich(bare_event(host_id, 900, 1), "boot-1", &mut resolver, &mut sessions);
        assert!(cron.session.is_none());
    }

    /// ARCHITECTURE.md §9.4 + plan Global Constraint #8: the edge is
    /// written once, on the PROCESS_EXEC event, and cites the authoritative
    /// process key.
    #[test]
    fn a_process_exec_inside_a_session_gains_a_triggered_by_session_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        let edges: Vec<_> = bash
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::TriggeredBySession)
            .collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].event_id, bash.event_id);
        match (&edges[0].from, &edges[0].to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::Session { session_id },
            ) => {
                assert_eq!(*process_key, bash.process.as_ref().unwrap().process_key);
                assert_eq!(session_id, "3");
            }
            other => panic!("expected a Process -> Session edge, got {other:?}"),
        }
    }

    #[test]
    fn a_process_exec_outside_a_session_gains_no_triggered_by_session_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let cron = enrich(bare_event(host_id, 900, 1), "boot-1", &mut resolver, &mut sessions);
        assert!(cron
            .relationships
            .iter()
            .all(|r| r.relation != Relation::TriggeredBySession));
    }

    #[test]
    fn a_real_uid_escalation_gains_an_executed_as_edge_to_the_target_user() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        let sudo = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver, &mut sessions);
        let escalation = enrich(
            privilege_event(host_id, 300, 200, 1000, Some(0)),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );

        let edges: Vec<_> = escalation
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::ExecutedAs)
            .collect();
        assert_eq!(edges.len(), 1);
        match (&edges[0].from, &edges[0].to) {
            (
                osiris_schema::EntityRef::Process { process_key },
                osiris_schema::EntityRef::User {
                    host_id: edge_host,
                    uid,
                },
            ) => {
                assert_eq!(*process_key, sudo.process.as_ref().unwrap().process_key);
                assert_eq!(*edge_host, host_id);
                assert_eq!(*uid, 0);
            }
            other => panic!("expected a Process -> User edge, got {other:?}"),
        }
        // The privilege event also inherits the session, which is what
        // makes Task 6's rule able to require a remote session.
        assert_eq!(
            escalation.session.as_ref().unwrap().remote_addr.as_deref(),
            Some("198.51.100.10")
        );
    }

    /// setuid(getuid()) is a no-op, not a privilege transition — minting an
    /// edge for it would fill the graph with self-loops (plan Global
    /// Constraint #8).
    #[test]
    fn a_uid_change_to_the_same_uid_gains_no_executed_as_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let event = enrich(
            privilege_event(host_id, 300, 200, 1000, Some(1000)),
            "boot-1",
            &mut resolver,
            &mut sessions,
        );
        assert!(event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs));
    }

    /// A sudo record with no reported target account (plan Global
    /// Constraint #9) must produce no edge rather than an invented one.
    #[test]
    fn a_privilege_event_without_a_target_uid_gains_no_executed_as_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let mut event = privilege_event(host_id, 300, 200, 1000, None);
        event.event_type = EventType::PrivilegeSudo;
        let event = enrich(event, "boot-1", &mut resolver, &mut sessions);
        assert!(event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs));
    }

    /// GC#8: EXECUTED_AS is attached on PRIVILEGE_UID_CHANGE only, never on
    /// PRIVILEGE_SUDO, even if a backend happens to populate target_uid on a
    /// sudo record (auditd's USER_CMD does not reliably carry it).
    #[test]
    fn a_privilege_sudo_event_with_a_target_uid_gains_no_executed_as_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let mut event = privilege_event(host_id, 300, 200, 1000, Some(0));
        event.event_type = EventType::PrivilegeSudo;
        let event = enrich(event, "boot-1", &mut resolver, &mut sessions);
        assert!(event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs));
    }

    /// Logout ends the session: a process that execs afterwards must not be
    /// attributed to it.
    #[test]
    fn a_logout_stops_further_processes_being_attributed_to_the_session() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();
        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);
        assert!(bash.session.is_some());

        let mut logout = login_event(host_id, 100);
        logout.event_type = EventType::SessionLogout;
        let _logout = enrich(logout, "boot-1", &mut resolver, &mut sessions);

        let after = enrich(bare_event(host_id, 400, 100), "boot-1", &mut resolver, &mut sessions);
        assert!(after.session.is_none());
    }

    /// Regression test for the Phase 4a final-review finding parked for
    /// this phase: an event that already carries an OBSERVED session
    /// (populated directly from the record's own `ses=` in Normalize, the
    /// same way `normalize_privilege_event` already works) must keep that
    /// session even when the pid/ppid chain would infer a *different* one —
    /// the nested-login (`su`) case where a pid moves from one real audit
    /// session into another.
    #[test]
    fn an_observed_session_wins_over_a_pid_inferred_one() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        // pid 100 is the root of session "3" (e.g. the original SSH login).
        let _login_a = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        // pid 200 execs under 100 and inherits session "3" by ppid chain.
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        // A second, independent login roots session "5" at pid 500 (e.g. a
        // concurrent console session, unrelated to pid 200's ancestry).
        let mut login_b = login_event(host_id, 500);
        login_b.session.as_mut().unwrap().session_id = "5".to_string();
        login_b.session.as_mut().unwrap().remote_addr = None;
        login_b.session.as_mut().unwrap().auth_method = Some("login".to_string());
        let _login_b = enrich(login_b, "boot-1", &mut resolver, &mut sessions);

        // pid 200 (a known member of session "3" via inheritance) now
        // produces an event whose record OWN `ses=` says "5" — e.g. it ran
        // `su` and its next audit-visible action is a Systemd/Privilege
        // record carrying the real, current, observed session. Normalize
        // would have populated `event.session` from that observation before
        // `enrich` ever runs; this test constructs that pre-enriched shape
        // directly, exactly as `normalize_privilege_event` and (this
        // phase's) `normalize_systemd_event` do.
        let mut observed_event = bare_event(host_id, 200, 100);
        observed_event.session = Some(SessionRef {
            session_id: "5".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        let result = enrich(observed_event, "boot-1", &mut resolver, &mut sessions);

        assert_eq!(
            result.session.as_ref().unwrap().session_id,
            "5",
            "the record's own observed session must win over the pid-inferred one"
        );
        assert_eq!(
            result.session.as_ref().unwrap().auth_method.as_deref(),
            Some("login"),
            "the observed session id must still be enriched from its own known record"
        );
    }

    /// When the observed session id does not (yet, or ever) match a known
    /// login record, the minimal observed ref must be kept exactly as
    /// Normalize produced it — not cleared, and not replaced by an
    /// unrelated pid-inferred session.
    #[test]
    fn an_observed_session_with_no_known_record_is_kept_minimal_not_overwritten() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let mut sessions = SessionResolver::new();

        let _login = enrich(login_event(host_id, 100), "boot-1", &mut resolver, &mut sessions);
        let _bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver, &mut sessions);

        // pid 200 is a known member of session "3", but this event's own
        // record observed a session ("9") the resolver has never heard of
        // (its login happened before the Agent started).
        let mut observed_event = bare_event(host_id, 200, 100);
        observed_event.session = Some(SessionRef {
            session_id: "9".to_string(),
            tty: None,
            remote_addr: None,
            auth_method: None,
        });
        let result = enrich(observed_event, "boot-1", &mut resolver, &mut sessions);

        assert_eq!(
            result.session.as_ref().unwrap().session_id,
            "9",
            "an unknown observed session must be kept, never silently swapped for pid-3"
        );
        assert!(result.session.as_ref().unwrap().tty.is_none());
    }
}
