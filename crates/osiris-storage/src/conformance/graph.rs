//! Conformance group `graph`: `write_relationships` and
//! `query_relationships`.

use osiris_schema::{CanonicalEvent, EntityRef, EntityRelationship, ProcessKey, Relation};
use uuid::Uuid;

use super::{assert_too_large, event_on, too_many_hosts};
use crate::{RelationshipQueryPlan, Storage};

pub fn writing_the_same_relationship_batch_twice_is_idempotent(s: &dyn Storage) {
    let edge = EntityRelationship {
        from: EntityRef::Process {
            process_key: ProcessKey::new(Uuid::new_v4(), "b", 1, 1),
        },
        to: EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        },
        relation: Relation::ConnectedTo,
        event_id: Uuid::now_v7(),
        timestamp: 5000,
    };
    s.write_relationships(std::slice::from_ref(&edge)).unwrap();
    s.write_relationships(std::slice::from_ref(&edge)).unwrap();
    let rows = s
        .query_relationships(&RelationshipQueryPlan::new())
        .unwrap();
    assert_eq!(rows.len(), 1);
}

pub fn write_and_query_relationships_round_trips_by_either_side_of_the_edge(s: &dyn Storage) {
    let host_id = Uuid::new_v4();
    let process_key = ProcessKey::new(host_id, "b", 300, 1);
    let event_id = Uuid::now_v7();
    let edge = EntityRelationship {
        from: EntityRef::Process { process_key },
        to: EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        },
        relation: Relation::ConnectedTo,
        event_id,
        timestamp: 5000,
    };

    let report = s.write_relationships(std::slice::from_ref(&edge)).unwrap();
    assert_eq!(report.written_count, 1);

    // Found by the `from` side.
    let by_from = s
        .query_relationships(&RelationshipQueryPlan {
            entity: Some(EntityRef::Process { process_key }),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_from.len(), 1);
    assert_eq!(by_from[0].event_id, event_id);
    assert_eq!(by_from[0].relation, Relation::ConnectedTo);

    // Found by the `to` side too: a caller need not know which side an
    // entity was recorded on.
    let by_to = s
        .query_relationships(&RelationshipQueryPlan {
            entity: Some(EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            }),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_to.len(), 1);
}

pub fn query_relationships_filters_by_time_range_and_limit(s: &dyn Storage) {
    let entity = EntityRef::Domain {
        name: "evil.example".to_string(),
    };
    let edges: Vec<EntityRelationship> = (0..3)
        .map(|i| EntityRelationship {
            from: entity.clone(),
            to: EntityRef::Session {
                session_id: i.to_string(),
            },
            relation: Relation::ResolvedTo,
            event_id: Uuid::now_v7(),
            timestamp: 1000 * (i + 1) as u64,
        })
        .collect();
    s.write_relationships(&edges).unwrap();

    let by_time = s
        .query_relationships(&RelationshipQueryPlan {
            entity: Some(entity.clone()),
            since: Some(1500),
            until: Some(2500),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_time.len(), 1);
    assert_eq!(by_time[0].timestamp, 2000);

    let limited = s
        .query_relationships(&RelationshipQueryPlan {
            entity: Some(entity),
            limit: 1,
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(limited.len(), 1);
}

pub fn host_ids_restricts_relationships_through_the_source_event(s: &dyn Storage) {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let ev_a = event_on(a, 1, 100);
    let ev_b = event_on(b, 2, 200);
    s.batch_write(&[ev_a.clone(), ev_b.clone()]).unwrap();
    let edge = |event: &CanonicalEvent| EntityRelationship {
        from: EntityRef::Ip {
            addr: "10.0.0.1".to_string(),
        },
        to: EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        },
        relation: Relation::ConnectedTo,
        event_id: event.event_id,
        timestamp: event.timestamp,
    };
    s.write_relationships(&[edge(&ev_a), edge(&ev_b)]).unwrap();
    let got = s
        .query_relationships(&RelationshipQueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].event_id, ev_a.event_id);
    assert!(s
        .query_relationships(&RelationshipQueryPlan {
            host_ids: Some(vec![]),
            ..RelationshipQueryPlan::new()
        })
        .unwrap()
        .is_empty());
}

pub fn an_oversized_host_set_is_a_clear_error_on_the_relationships_path(s: &dyn Storage) {
    assert_too_large(s.query_relationships(&RelationshipQueryPlan {
        host_ids: Some(too_many_hosts()),
        ..RelationshipQueryPlan::new()
    }));
}
