use std::collections::{HashMap, HashSet};

use osiris_query::ast::{Ast, Op, Value};
use osiris_query::EventQueryPlan;
use osiris_schema::CanonicalEvent;
use osiris_storage::{Storage, StorageError};

use crate::support::{assemble, Story};

fn dns_domain_plan(domain: &str) -> EventQueryPlan {
    EventQueryPlan {
        filter: Some(Ast::Compare {
            field: "dns.query".to_string(),
            op: Op::Eq,
            value: Value::Str(domain.to_string()),
        }),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

fn network_addr_plan(addr: &str) -> EventQueryPlan {
    let ast = Ast::Or(
        Box::new(Ast::Compare { field: "network.src_ip".to_string(), op: Op::Eq, value: Value::Str(addr.to_string()) }),
        Box::new(Ast::Compare { field: "network.dst_ip".to_string(), op: Op::Eq, value: Value::Str(addr.to_string()) }),
    );
    EventQueryPlan {
        filter: Some(ast),
        limit: 10_000,
        export: true,
        ..EventQueryPlan::new()
    }
}

/// ARCHITECTURE.md §12.1's Network Story, refactored from `osiris-api`'s
/// former `network_story_handler` — the same disclosed asymmetry as
/// before: the domain form resolves DNS then unions in network events
/// touching any resolved address; the IP form matches network events
/// directly and does not reverse-resolve to the DNS side.
pub fn network_story(storage: &dyn Storage, ip: Option<&str>, domain: Option<&str>) -> Result<Story, StorageError> {
    let mut events_by_id: HashMap<uuid::Uuid, CanonicalEvent> = HashMap::new();

    if let Some(domain) = domain {
        let dns_events = storage.query_events(&dns_domain_plan(domain))?;
        let mut resolved_ips: HashSet<String> = HashSet::new();
        for e in &dns_events {
            if let Some(dns) = &e.dns {
                resolved_ips.extend(dns.response_ips.iter().cloned());
            }
        }
        for e in dns_events {
            events_by_id.insert(e.event_id, e);
        }
        for addr in &resolved_ips {
            for e in storage.query_events(&network_addr_plan(addr))? {
                events_by_id.insert(e.event_id, e);
            }
        }
    }

    if let Some(ip) = ip {
        for e in storage.query_events(&network_addr_plan(ip))? {
            events_by_id.insert(e.event_id, e);
        }
    }

    assemble(storage, events_by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, DnsRef, EventType, HostRef, NetworkDirection, NetworkRef, Severity, Source,
        SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(event_type: EventType, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type,
            category: Category::Network,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None, session: None, process: None, parent_process: None, thread: None, file: None,
            network: None, dns: None, device: None, service: None, container: None, namespace: None,
            cgroup: None, kernel: None, source: Source::Synthetic, provider: "test".to_string(),
            raw_event: None, relationships: vec![], tags: vec![], risk: None, event_data: serde_json::json!({}),
        }
    }

    fn dns_event(query: &str, response_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = base_event(EventType::DnsQuery, timestamp);
        e.dns = Some(DnsRef {
            query: query.to_string(),
            qtype: "A".to_string(),
            response_ips: vec![response_ip.to_string()],
            ttl: None,
        });
        e
    }

    fn network_event(src_ip: &str, dst_ip: &str, timestamp: u64) -> CanonicalEvent {
        let mut e = base_event(EventType::NetworkConnect, timestamp);
        e.network = Some(NetworkRef {
            src_ip: src_ip.to_string(),
            src_port: 12345,
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            bytes: None,
        });
        e
    }

    #[test]
    fn network_story_by_domain_unions_in_events_touching_the_resolved_ip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&dns_event("evil.example", "203.0.113.10", 100)).unwrap();
        storage.write(&network_event("10.0.0.5", "203.0.113.10", 200)).unwrap();
        storage.write(&network_event("10.0.0.5", "198.51.100.1", 300)).unwrap();

        let story = network_story(&storage, None, Some("evil.example")).unwrap();
        assert_eq!(story.events.len(), 2, "the DNS event and the one matching network event");
    }

    #[test]
    fn network_story_by_ip_matches_either_side_of_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        storage.write(&network_event("203.0.113.10", "10.0.0.5", 100)).unwrap();
        storage.write(&network_event("10.0.0.5", "203.0.113.10", 200)).unwrap();
        storage.write(&network_event("10.0.0.5", "198.51.100.1", 300)).unwrap();

        let story = network_story(&storage, Some("203.0.113.10"), None).unwrap();
        assert_eq!(story.events.len(), 2);
    }
}
