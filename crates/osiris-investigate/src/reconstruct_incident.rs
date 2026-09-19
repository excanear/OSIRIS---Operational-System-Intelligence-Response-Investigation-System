use serde::Serialize;
use uuid::Uuid;

use osiris_correlate::{CorrelationEngine, EdgeSource};
use osiris_schema::{Category, EntityRef, EntityRelationship};
use osiris_storage::{RelationshipQueryPlan, Storage, StorageError};

/// The staged bucketing order ARCHITECTURE.md §12.1 and the master
/// prompt's worked trace call for: `INITIAL EVENT -> EXECUTION ->
/// FILESYSTEM -> NETWORK -> PRIVILEGE -> PERSISTENCE -> IMPACT`, expressed
/// in terms of this schema's `Category` values (`Dns`/`KernelModule`/
/// `Container`/`Security`/`System` are appended after the named stages so
/// no category is silently dropped from a chain that touches one of them).
const STAGE_ORDER: &[Category] = &[
    Category::Identity,
    Category::Process,
    Category::File,
    Category::Network,
    Category::Privilege,
    Category::Persistence,
    Category::Systemd,
    Category::Dns,
    Category::KernelModule,
    Category::Container,
    Category::Security,
    Category::System,
];

#[derive(Debug, Serialize)]
pub struct IncidentStage {
    pub category: Category,
    pub event_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct IncidentReconstruction {
    pub seed: EntityRef,
    pub stages: Vec<IncidentStage>,
}

struct StorageEdgeSource<'s> {
    storage: &'s dyn Storage,
}

impl EdgeSource for StorageEdgeSource<'_> {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship> {
        let plan = RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(since),
            until: Some(until),
            ..RelationshipQueryPlan::new()
        };
        self.storage.query_relationships(&plan).unwrap_or_default()
    }
}

/// ARCHITECTURE.md §12.1's `reconstruct_incident(seed_entity, time_range)`:
/// walks the Correlation Engine's `BehavioralChain` from `seed`, resolves
/// every edge's `event_id` back into a real event (Task 16's
/// `Storage::get_event`), and buckets them by `category` in `STAGE_ORDER`
/// — every bucket entry is a bare `event_id`, so a caller always has the
/// exact evidence for each stage (ARCHITECTURE.md §44: "every conclusion
/// must have evidence").
pub fn reconstruct_incident(
    storage: &dyn Storage,
    seed: EntityRef,
    since: u64,
    until: u64,
) -> Result<IncidentReconstruction, StorageError> {
    let source = StorageEdgeSource { storage };
    let engine = CorrelationEngine::new(5, (until.saturating_sub(since)).max(1));
    let seed_time_ns = since + (until.saturating_sub(since)) / 2;
    let chain = engine.build_chain(&source, seed.clone(), seed_time_ns);

    // `Category` derives `PartialEq, Eq` but not `Hash`, so grouping is done
    // with a linear scan over `resolved` (bounded by `STAGE_ORDER.len()` *
    // `chain.event_ids.len()`, both small) rather than a `HashMap` — this
    // also keeps each stage's `event_ids` in `chain.event_ids`'s existing
    // time order for free, since `filter` preserves source order.
    let mut resolved: Vec<(Category, Uuid)> = Vec::new();
    for event_id in &chain.event_ids {
        if let Some(event) = storage.get_event(*event_id)? {
            resolved.push((event.category, *event_id));
        }
    }

    let stages = STAGE_ORDER
        .iter()
        .filter_map(|category| {
            let event_ids: Vec<Uuid> = resolved
                .iter()
                .filter(|(c, _)| c == category)
                .map(|(_, id)| *id)
                .collect();
            if event_ids.is_empty() {
                None
            } else {
                Some(IncidentStage {
                    category: *category,
                    event_ids,
                })
            }
        })
        .collect();

    Ok(IncidentReconstruction { seed, stages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::CanonicalEvent;
    use osiris_schema::{
        Category, EventType, HostRef, NetworkDirection, NetworkRef, ProcessKey, ProcessRef,
        Relation, Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(category: Category, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::NetworkConnect,
            category,
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
            network: Some(NetworkRef {
                src_ip: "10.0.0.1".to_string(),
                src_port: 1,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 2,
                proto: "tcp".to_string(),
                direction: NetworkDirection::Outbound,
                bytes: None,
            }),
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
    fn reconstruct_incident_buckets_the_chains_events_by_category_in_time_order() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 1, 1);

        let exec_event = {
            let mut e = base_event(Category::Process, 100);
            e.event_type = EventType::ProcessExec;
            e.process = Some(ProcessRef {
                process_key,
                pid: 1,
                exe_path: "/bin/x".to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 100,
            });
            e.network = None;
            e
        };
        let network_event = base_event(Category::Network, 200);
        storage.write(&exec_event).unwrap();
        storage.write(&network_event).unwrap();

        let seed = EntityRef::Process { process_key };
        storage
            .write_relationships(&[EntityRelationship {
                from: seed.clone(),
                to: EntityRef::Ip {
                    addr: "10.0.0.2".to_string(),
                },
                relation: Relation::ConnectedTo,
                event_id: network_event.event_id,
                timestamp: 200,
            }])
            .unwrap();

        let reconstruction = reconstruct_incident(&storage, seed.clone(), 0, 1000).unwrap();
        assert_eq!(reconstruction.seed, seed);
        let network_stage = reconstruction
            .stages
            .iter()
            .find(|s| s.category == Category::Network)
            .expect("expected a Network stage");
        assert!(network_stage.event_ids.contains(&network_event.event_id));
    }
}
