use std::collections::HashSet;

use serde::Serialize;
use uuid::Uuid;

use osiris_schema::{EntityRef, EntityRelationship, Relation};
use osiris_storage::{RelationshipQueryPlan, Storage, StorageError};

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: Relation,
    pub event_id: Uuid,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct Subgraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// `true` when more of the reachable graph existed than `max_nodes`
    /// allowed in — ARCHITECTURE.md §12.5's "never the full graph" made
    /// visible to the caller rather than silently clipped.
    pub truncated: bool,
}

fn kind_of(entity: &EntityRef) -> &'static str {
    match entity {
        EntityRef::Process { .. } => "PROCESS",
        EntityRef::File { .. } => "FILE",
        EntityRef::Ip { .. } => "IP",
        EntityRef::Domain { .. } => "DOMAIN",
        EntityRef::User { .. } => "USER",
        EntityRef::Container { .. } => "CONTAINER",
        EntityRef::Session { .. } => "SESSION",
    }
}

/// Entity Graph v2 (ARCHITECTURE.md §12.5): a bounded-depth **and**
/// bounded-node-count BFS from `seed`, returned as a generic node/edge
/// shape any graph UI can render — distinct from and additive to
/// `/api/v1/graph`'s existing `BehavioralChain` response, which stays
/// depth-bounded only and keeps serving callers that want that specific
/// shape (plan Global Constraint #4's spirit, extended to this endpoint
/// even though `/graph/subgraph` itself is new).
pub fn subgraph(
    storage: &dyn Storage,
    seed: EntityRef,
    max_depth: usize,
    max_nodes: usize,
    since: u64,
    until: u64,
) -> Result<Subgraph, StorageError> {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(seed.storage_key());
    let mut nodes = vec![GraphNode {
        id: seed.storage_key(),
        kind: kind_of(&seed).to_string(),
    }];
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut seen_edges: HashSet<(String, String, Uuid)> = HashSet::new();
    let mut frontier = vec![seed];
    let mut truncated = false;

    for _ in 0..max_depth {
        if frontier.is_empty() {
            break;
        }
        let mut next_frontier = Vec::new();
        for entity in &frontier {
            let plan = RelationshipQueryPlan {
                entity: Some(entity.clone()),
                since: Some(since),
                until: Some(until),
                ..RelationshipQueryPlan::new()
            };
            let rels: Vec<EntityRelationship> = storage.query_relationships(&plan)?;
            for rel in rels {
                let edge_key = (rel.from.storage_key(), rel.to.storage_key(), rel.event_id);
                if !seen_edges.insert(edge_key) {
                    continue;
                }
                let this_key = entity.storage_key();
                let other = if rel.from.storage_key() == this_key {
                    rel.to.clone()
                } else {
                    rel.from.clone()
                };
                let other_key = other.storage_key();
                if !visited.contains(&other_key) {
                    if nodes.len() >= max_nodes {
                        // The edge would point at a node this response
                        // doesn't include — record the truncation and
                        // drop the edge too, rather than emit a dangling
                        // reference.
                        truncated = true;
                        continue;
                    }
                    visited.insert(other_key.clone());
                    nodes.push(GraphNode {
                        id: other_key,
                        kind: kind_of(&other).to_string(),
                    });
                    next_frontier.push(other);
                }
                edges.push(GraphEdge {
                    from: rel.from.storage_key(),
                    to: rel.to.storage_key(),
                    relation: rel.relation,
                    event_id: rel.event_id,
                    timestamp: rel.timestamp,
                });
            }
        }
        frontier = next_frontier;
    }

    Ok(Subgraph {
        nodes,
        edges,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_storage_sqlite::SqliteStorage;

    fn edge(from: EntityRef, to: EntityRef, timestamp: u64) -> EntityRelationship {
        EntityRelationship {
            from,
            to,
            relation: Relation::ConnectedTo,
            event_id: Uuid::now_v7(),
            timestamp,
        }
    }

    #[test]
    fn subgraph_stops_expanding_once_max_nodes_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let seed = EntityRef::Ip {
            addr: "10.0.0.1".to_string(),
        };
        // seed -> a -> b -> c -> d, a chain of 5 distinct nodes
        let a = EntityRef::Ip {
            addr: "10.0.0.2".to_string(),
        };
        let b = EntityRef::Ip {
            addr: "10.0.0.3".to_string(),
        };
        let c = EntityRef::Ip {
            addr: "10.0.0.4".to_string(),
        };
        let d = EntityRef::Ip {
            addr: "10.0.0.5".to_string(),
        };
        storage
            .write_relationships(&[
                edge(seed.clone(), a.clone(), 100),
                edge(a.clone(), b.clone(), 200),
                edge(b.clone(), c.clone(), 300),
                edge(c.clone(), d.clone(), 400),
            ])
            .unwrap();

        let result = subgraph(&storage, seed.clone(), 10, 3, 0, 1000).unwrap();
        assert!(result.nodes.len() <= 3);
        assert!(result.truncated);
    }

    #[test]
    fn subgraph_reports_not_truncated_when_everything_reachable_fits() {
        let dir = tempfile::tempdir().unwrap();
        let storage = SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let seed = EntityRef::Ip {
            addr: "10.0.0.1".to_string(),
        };
        let a = EntityRef::Ip {
            addr: "10.0.0.2".to_string(),
        };
        storage
            .write_relationships(&[edge(seed.clone(), a.clone(), 100)])
            .unwrap();

        let result = subgraph(&storage, seed, 10, 100, 0, 1000).unwrap();
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.edges.len(), 1);
        assert!(!result.truncated);
    }
}
