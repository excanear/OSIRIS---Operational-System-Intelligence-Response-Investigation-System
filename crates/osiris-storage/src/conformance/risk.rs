//! Conformance group `risk`: `write_risk_scores` / `query_risk_scores`, plus
//! the tests that exercise every side table together (alerts, relationships
//! and risk scores), so they only run once all of those exist.

use osiris_schema::{
    EntityRef, EntityRelationship, ProcessKey, Relation, Severity, WeightedReason,
};
use uuid::Uuid;

use super::{
    alert_on, assert_too_large, event_on, max_hosts_including, sample_risk_record, too_many_hosts,
};
use crate::{AlertQueryPlan, DeleteCriteria, RelationshipQueryPlan, RiskQueryPlan, Storage};

pub fn write_and_query_risk_scores_round_trips_reasons_intact(s: &dyn Storage) {
    let process_key = ProcessKey::new(Uuid::new_v4(), "b", 300, 1);
    let record = sample_risk_record(Some(process_key), 5000);

    let report = s.write_risk_scores(std::slice::from_ref(&record)).unwrap();
    assert_eq!(report.written_count, 1);

    let by_process = s
        .query_risk_scores(&RiskQueryPlan {
            process_key: Some(process_key),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_process.len(), 1);
    assert_eq!(by_process[0].score, 42);
    assert_eq!(by_process[0].severity, Severity::High);
    assert_eq!(by_process[0].reasons.len(), 1);
    assert_eq!(by_process[0].reasons[0].label, "Rare executable path");
    assert_eq!(by_process[0].reasons[0].weight, 10);

    let by_event = s
        .query_risk_scores(&RiskQueryPlan {
            event_id: Some(record.event_id),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_event.len(), 1);
    assert_eq!(by_event[0].event_id, record.event_id);
}

pub fn host_ids_restricts_alerts_and_risk_scores(s: &dyn Storage) {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    s.write_alerts(&[
        alert_on(a, vec![Uuid::now_v7()], "r1", 10),
        alert_on(b, vec![Uuid::now_v7()], "r1", 10),
    ])
    .unwrap();
    let got = s
        .query_alerts(&AlertQueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id(), a);
    assert!(s
        .query_alerts(&AlertQueryPlan {
            host_ids: Some(vec![]),
            ..AlertQueryPlan::new()
        })
        .unwrap()
        .is_empty());

    let mut ra = sample_risk_record(None, 10);
    ra.host_id = a;
    let mut rb = sample_risk_record(None, 20);
    rb.host_id = b;
    s.write_risk_scores(&[ra, rb]).unwrap();
    let got = s
        .query_risk_scores(&RiskQueryPlan {
            host_ids: Some(vec![b.to_string()]),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id, b);
}

/// One event on `host` at `timestamp`, plus an alert, an edge and a risk
/// record that all cite it.
fn write_one_of_each(
    s: &dyn Storage,
    host: Uuid,
    timestamp: u64,
) -> (osiris_schema::CanonicalEvent, EntityRef) {
    let event = event_on(host, 1, timestamp);
    s.write(&event).unwrap();
    s.write_alerts(&[alert_on(host, vec![event.event_id], "rule_a", timestamp)])
        .unwrap();
    let entity = EntityRef::Ip {
        addr: "203.0.113.10".to_string(),
    };
    s.write_relationships(&[EntityRelationship {
        from: EntityRef::Process {
            process_key: event.process.as_ref().unwrap().process_key,
        },
        to: entity.clone(),
        relation: Relation::ConnectedTo,
        event_id: event.event_id,
        timestamp,
    }])
    .unwrap();
    let mut record = sample_risk_record(None, timestamp);
    record.event_id = event.event_id;
    record.host_id = host;
    s.write_risk_scores(&[record]).unwrap();
    (event, entity)
}

pub fn delete_leaves_alerts_relationships_and_risk_intact(s: &dyn Storage) {
    let (event, entity) = write_one_of_each(s, Uuid::new_v4(), 1000);

    let deleted = s
        .delete(&DeleteCriteria {
            before_timestamp: 1001,
        })
        .unwrap();
    assert_eq!(deleted, 1);
    assert!(s.get_event(event.event_id).unwrap().is_none());

    let alerts = s
        .query_alerts(&AlertQueryPlan {
            evidence_event_ids: vec![event.event_id],
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(alerts.len(), 1);
    let edges = s
        .query_relationships(&RelationshipQueryPlan {
            entity: Some(entity),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(edges.len(), 1);
    let risk = s
        .query_risk_scores(&RiskQueryPlan {
            event_id: Some(event.event_id),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(risk.len(), 1);
}

pub fn full_u64_time_window_on_side_tables(s: &dyn Storage) {
    write_one_of_each(s, Uuid::new_v4(), 1000);

    let alerts = s
        .query_alerts(&AlertQueryPlan {
            since: Some(0),
            until: Some(u64::MAX),
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(alerts.len(), 1);
    let edges = s
        .query_relationships(&RelationshipQueryPlan {
            since: Some(0),
            until: Some(u64::MAX),
            ..RelationshipQueryPlan::new()
        })
        .unwrap();
    assert_eq!(edges.len(), 1);
    let risk = s
        .query_risk_scores(&RiskQueryPlan {
            since: Some(0),
            until: Some(u64::MAX),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(risk.len(), 1);
}

pub fn max_size_host_set_on_side_tables(s: &dyn Storage) {
    let real = Uuid::new_v4();
    write_one_of_each(s, real, 1000);
    write_one_of_each(s, Uuid::new_v4(), 2000);

    let alerts = |hosts| AlertQueryPlan {
        host_ids: Some(hosts),
        ..AlertQueryPlan::new()
    };
    let edges = |hosts| RelationshipQueryPlan {
        host_ids: Some(hosts),
        ..RelationshipQueryPlan::new()
    };
    let risk = |hosts| RiskQueryPlan {
        host_ids: Some(hosts),
        ..RiskQueryPlan::new()
    };

    let got = s.query_alerts(&alerts(max_hosts_including(real))).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id(), real);
    assert_eq!(
        s.query_relationships(&edges(max_hosts_including(real)))
            .unwrap()
            .len(),
        1
    );
    let got = s
        .query_risk_scores(&risk(max_hosts_including(real)))
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id, real);

    assert_too_large(s.query_alerts(&alerts(too_many_hosts())));
    assert_too_large(s.query_relationships(&edges(too_many_hosts())));
    assert_too_large(s.query_risk_scores(&risk(too_many_hosts())));
}

pub fn risk_reasons_keep_their_written_order(s: &dyn Storage) {
    let mut record = sample_risk_record(None, 1000);
    let evidence = record.event_id;
    record.reasons = ["c", "a", "b"]
        .iter()
        .enumerate()
        .map(|(i, label)| WeightedReason {
            label: label.to_string(),
            weight: 10 + i as i16,
            evidence,
        })
        .collect();
    s.write_risk_scores(std::slice::from_ref(&record)).unwrap();

    let got = s
        .query_risk_scores(&RiskQueryPlan {
            event_id: Some(evidence),
            ..RiskQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    let labels: Vec<&str> = got[0].reasons.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["c", "a", "b"]);
}
