use std::collections::HashSet;

use osiris_schema::{EntityRef, EntityRelationship};
use uuid::Uuid;

/// A source of relationship edges for one entity within a time window.
/// Deliberately not `osiris_storage::Storage` itself — this crate stays
/// decoupled from the storage layer (ARCHITECTURE.md §27's dependency
/// graph never draws an edge from `osiris-correlate` to `osiris-storage`;
/// `osiris-server`, which links both, provides the adapter — Phase 6 plan
/// Task 10). This is also what keeps `CorrelationEngine::build_chain`
/// testable with a trivial in-memory double, with no database involved.
pub trait EdgeSource {
    fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship>;
}

/// The result of one graph walk (ARCHITECTURE.md §11.3): the deduplicated
/// edges reached from `seed` within the walk's depth/time bounds, and the
/// deduplicated, time-ordered set of every edge's `event_id` — the input
/// `§12.1`'s `*Story`/`§14.4`'s `reconstruct_incident` compose on top of.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BehavioralChain {
    pub seed: EntityRef,
    pub edges: Vec<EntityRelationship>,
    pub event_ids: Vec<Uuid>,
}

impl BehavioralChain {
    /// True when the chain contains at least one edge of `relation`
    /// originating at (or terminating at) `entity` — the primitive the
    /// Risk Engine's chain-pattern bonus (Phase 6 plan Task 6) is built on.
    pub fn has_relation_touching(
        &self,
        entity: &EntityRef,
        relation: osiris_schema::Relation,
    ) -> bool {
        let key = entity.storage_key();
        self.edges.iter().any(|e| {
            e.relation == relation && (e.from.storage_key() == key || e.to.storage_key() == key)
        })
    }
}

/// Bounded graph-walk builder (ARCHITECTURE.md §11.3: "implemented as a
/// graph walk over the entity graph... seeded from a trigger event, bounded
/// by depth and time window").
#[derive(Debug, Clone, Copy)]
pub struct CorrelationEngine {
    pub max_depth: usize,
    pub window_ns: u64,
}

impl CorrelationEngine {
    pub fn new(max_depth: usize, window_ns: u64) -> Self {
        Self {
            max_depth,
            window_ns,
        }
    }

    /// BFS from `seed`, bounded by `max_depth` hops and
    /// `[seed_time_ns - window_ns, seed_time_ns + window_ns]`. Cycle-safe:
    /// an entity (e.g., a shared IP/domain) is enqueued into the frontier
    /// at most once, and an edge is counted at most once even if reachable
    /// from both of its endpoints during the walk.
    pub fn build_chain(
        &self,
        source: &impl EdgeSource,
        seed: EntityRef,
        seed_time_ns: u64,
    ) -> BehavioralChain {
        let since = seed_time_ns.saturating_sub(self.window_ns);
        let until = seed_time_ns.saturating_add(self.window_ns);

        let mut visited_entities: HashSet<String> = HashSet::new();
        visited_entities.insert(seed.storage_key());
        let mut visited_edges: HashSet<(String, String, Uuid)> = HashSet::new();
        let mut frontier = vec![seed.clone()];
        let mut all_edges: Vec<EntityRelationship> = Vec::new();

        for _ in 0..self.max_depth {
            if frontier.is_empty() {
                break;
            }
            let mut next_frontier = Vec::new();
            for entity in &frontier {
                for edge in source.edges_for(entity, since, until) {
                    let edge_key = (
                        edge.from.storage_key(),
                        edge.to.storage_key(),
                        edge.event_id,
                    );
                    if !visited_edges.insert(edge_key) {
                        continue;
                    }
                    let entity_key = entity.storage_key();
                    let other = if edge.from.storage_key() == entity_key {
                        edge.to.clone()
                    } else {
                        edge.from.clone()
                    };
                    if visited_entities.insert(other.storage_key()) {
                        next_frontier.push(other);
                    }
                    all_edges.push(edge);
                }
            }
            frontier = next_frontier;
        }

        all_edges.sort_by_key(|e| e.timestamp);
        let mut seen_events: HashSet<Uuid> = HashSet::new();
        let mut event_ids = Vec::new();
        for edge in &all_edges {
            if seen_events.insert(edge.event_id) {
                event_ids.push(edge.event_id);
            }
        }

        BehavioralChain {
            seed,
            edges: all_edges,
            event_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::Relation;
    use std::collections::HashMap;

    /// An in-memory `EdgeSource` test double, indexed by every entity a
    /// stored edge touches (from either side) so a lookup does not need to
    /// know which side an edge was recorded on — mirroring what
    /// `SqliteStorage::query_relationships` (Phase 6 plan Task 3) actually
    /// does.
    struct FakeEdgeSource {
        by_entity: HashMap<String, Vec<EntityRelationship>>,
    }

    impl FakeEdgeSource {
        fn new(edges: Vec<EntityRelationship>) -> Self {
            let mut by_entity: HashMap<String, Vec<EntityRelationship>> = HashMap::new();
            for edge in edges {
                by_entity
                    .entry(edge.from.storage_key())
                    .or_default()
                    .push(edge.clone());
                by_entity
                    .entry(edge.to.storage_key())
                    .or_default()
                    .push(edge);
            }
            Self { by_entity }
        }
    }

    impl EdgeSource for FakeEdgeSource {
        fn edges_for(&self, entity: &EntityRef, since: u64, until: u64) -> Vec<EntityRelationship> {
            self.by_entity
                .get(&entity.storage_key())
                .into_iter()
                .flatten()
                .filter(|e| e.timestamp >= since && e.timestamp <= until)
                .cloned()
                .collect()
        }
    }

    fn session() -> EntityRef {
        EntityRef::Session {
            session_id: "3".to_string(),
        }
    }
    // A deterministic key (not `Uuid::new_v4()`, which would mint a
    // different entity — and a different `storage_key()` — on every call)
    // so every `process()` call within one test refers to the same entity.
    fn process() -> EntityRef {
        EntityRef::Process {
            process_key: osiris_schema::ProcessKey::new(Uuid::nil(), "b", 300, 1),
        }
    }
    fn file() -> EntityRef {
        EntityRef::File {
            host_id: Uuid::nil(),
            inode: 1,
            device_id: 2049,
        }
    }
    fn ip() -> EntityRef {
        EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        }
    }

    fn edge(
        from: EntityRef,
        to: EntityRef,
        relation: Relation,
        timestamp: u64,
    ) -> EntityRelationship {
        EntityRelationship {
            from,
            to,
            relation,
            event_id: Uuid::now_v7(),
            timestamp,
        }
    }

    /// Mirrors ARCHITECTURE.md §26's worked trace shape: a session spawns a
    /// process, which connects to the network and writes a file — all
    /// reachable within depth/window.
    #[test]
    fn a_session_process_file_and_network_chain_is_fully_reachable() {
        let edges = vec![
            edge(session(), process(), Relation::Spawned, 1000),
            edge(process(), ip(), Relation::ConnectedTo, 2000),
            edge(process(), file(), Relation::Wrote, 3000),
        ];
        let source = FakeEdgeSource::new(edges);
        let engine = CorrelationEngine::new(5, 10_000);

        let chain = engine.build_chain(&source, session(), 1000);
        assert_eq!(chain.edges.len(), 3);
        assert_eq!(chain.event_ids.len(), 3);
        assert!(chain.has_relation_touching(&process(), Relation::ConnectedTo));
        assert!(chain.has_relation_touching(&process(), Relation::Wrote));
    }

    #[test]
    fn an_edge_outside_the_time_window_is_excluded() {
        let edges = vec![
            edge(session(), process(), Relation::Spawned, 1000),
            edge(process(), ip(), Relation::ConnectedTo, 100_000),
        ];
        let source = FakeEdgeSource::new(edges);
        let engine = CorrelationEngine::new(5, 5_000);

        let chain = engine.build_chain(&source, session(), 1000);
        assert_eq!(chain.edges.len(), 1);
        assert_eq!(chain.edges[0].relation, Relation::Spawned);
    }

    #[test]
    fn depth_limit_truncates_a_long_chain() {
        // session -> process -> file -> (another hop the depth limit cuts off)
        let far = EntityRef::Domain {
            name: "far.example".to_string(),
        };
        let edges = vec![
            edge(session(), process(), Relation::Spawned, 1000),
            edge(process(), file(), Relation::Wrote, 2000),
            edge(file(), far, Relation::ResolvedTo, 3000),
        ];
        let source = FakeEdgeSource::new(edges);
        let engine = CorrelationEngine::new(2, 10_000);

        let chain = engine.build_chain(&source, session(), 1000);
        // Depth 1: session->process. Depth 2: process->file. The third hop
        // (file->far) would be depth 3, beyond max_depth=2.
        assert_eq!(chain.edges.len(), 2);
    }

    #[test]
    fn a_diamond_shared_entity_does_not_duplicate_edges_or_revisit() {
        // Two processes both connect to the same IP — the IP must not be
        // walked twice, and the two edges into it must both still appear
        // exactly once each.
        let process_b = EntityRef::Process {
            process_key: osiris_schema::ProcessKey::new(Uuid::new_v4(), "b", 301, 1),
        };
        let edges = vec![
            edge(session(), process(), Relation::Spawned, 1000),
            edge(session(), process_b.clone(), Relation::Spawned, 1000),
            edge(process(), ip(), Relation::ConnectedTo, 2000),
            edge(process_b, ip(), Relation::ConnectedTo, 2000),
        ];
        let source = FakeEdgeSource::new(edges);
        let engine = CorrelationEngine::new(5, 10_000);

        let chain = engine.build_chain(&source, session(), 1000);
        assert_eq!(chain.edges.len(), 4);
        assert_eq!(chain.event_ids.len(), 4);
    }

    #[test]
    fn event_ids_are_deduplicated_and_time_ordered() {
        let event_id = Uuid::now_v7();
        let mut e1 = edge(session(), process(), Relation::Spawned, 2000);
        e1.event_id = event_id;
        let mut e2 = edge(process(), file(), Relation::Wrote, 1000);
        e2.event_id = event_id; // same event produced two edges
        let source = FakeEdgeSource::new(vec![e1, e2]);
        let engine = CorrelationEngine::new(5, 10_000);

        let chain = engine.build_chain(&source, session(), 1500);
        assert_eq!(chain.event_ids, vec![event_id]);
    }
}
