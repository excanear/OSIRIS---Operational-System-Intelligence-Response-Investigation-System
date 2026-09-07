use osiris_schema::{
    CanonicalEvent, Category, EntityRef, EntityRelationship, EventType, FileIdentity, ProcessRef,
    Relation,
};

use crate::process_resolver::ProcessResolver;

/// Enrich (local) stage (ARCHITECTURE.md §7.1 step 3): attach host/boot
/// identity, resolve process identity via the Process Resolver, and compute
/// the entity-graph edges §9.4 requires be written once here rather than
/// re-derived by every consumer. Cheap, always-available context only —
/// expensive enrichment is server-side (§7.2's split is preserved by simply
/// not doing that work yet, not by doing it here).
pub fn enrich(
    mut event: CanonicalEvent,
    boot_id: &str,
    resolver: &mut ProcessResolver,
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

    match event.category {
        Category::File => attach_file_relationship(&mut event),
        Category::Network => attach_network_relationship(&mut event),
        Category::Dns => attach_dns_relationships(&mut event),
        _ => {}
    }

    event
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
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
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
        let file_event = enrich(
            bare_file_event(host_id, 777, 1, 131075),
            "boot-1",
            &mut resolver,
        );
        assert!(file_event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }

    #[test]
    fn file_event_resolves_its_parent_process_from_the_resolver() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let bash = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);
        let _curl = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
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
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let file_event = enrich(
            bare_file_event(host_id, 300, 200, 131075),
            "boot-1",
            &mut resolver,
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
        let mut event = bare_file_event(host_id, 300, 200, 131075);
        if let Some(file) = event.file.as_mut() {
            file.inode = None;
        }
        let enriched = enrich(event, "boot-1", &mut resolver);
        assert!(enriched.relationships.is_empty());
    }

    /// Regression guard: the Process branch's behaviour (record, then
    /// resolve the parent by the ppid carried in event_data) must be
    /// untouched by the new non-process path.
    #[test]
    fn process_events_still_record_and_resolve_exactly_as_before() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let bash = enrich(bare_event(host_id, 100, 1), "boot-1", &mut resolver);
        let curl = enrich(bare_event(host_id, 200, 100), "boot-1", &mut resolver);
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
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let net_event = enrich(
            bare_network_event(host_id, Some(300), "203.0.113.50"),
            "boot-1",
            &mut resolver,
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
        let net_event = enrich(
            bare_network_event(host_id, None, "203.0.113.50"),
            "boot-1",
            &mut resolver,
        );
        assert!(net_event.relationships.is_empty());
        assert!(net_event.process.is_none());
    }

    #[test]
    fn network_close_event_gets_no_connected_to_edge() {
        let host_id = Uuid::new_v4();
        let mut resolver = ProcessResolver::new();
        let _curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let mut event = bare_network_event(host_id, Some(300), "203.0.113.50");
        event.event_type = EventType::NetworkClose;
        let closed = enrich(event, "boot-1", &mut resolver);
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
        let dns_event = enrich(
            bare_dns_event(
                host_id,
                Some(300),
                vec!["203.0.113.50".to_string(), "203.0.113.51".to_string()],
            ),
            "boot-1",
            &mut resolver,
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
        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec![]),
            "boot-1",
            &mut resolver,
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
        let curl_exec = enrich(bare_event(host_id, 300, 200), "boot-1", &mut resolver);
        let authoritative = curl_exec.process.unwrap().process_key;

        let dns_event = enrich(
            bare_dns_event(host_id, Some(300), vec!["203.0.113.50".to_string()]),
            "boot-1",
            &mut resolver,
        );
        assert_eq!(dns_event.process.unwrap().process_key, authoritative);
        assert!(!dns_event.tags.contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
    }
}
