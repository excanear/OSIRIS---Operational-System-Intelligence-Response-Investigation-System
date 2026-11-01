//! Conformance group `alerts`: `write_alerts` and `query_alerts`.

use uuid::Uuid;

use super::sample_alert;
use crate::{AlertQueryPlan, Storage};

pub fn write_and_query_alerts_round_trips(s: &dyn Storage) {
    let event_id = Uuid::now_v7();
    let alert = sample_alert(vec![event_id], "shell_wrote_file_to_web_root", 5000);

    let report = s.write_alerts(std::slice::from_ref(&alert)).unwrap();
    assert_eq!(report.written_count, 1);

    let results = s.query_alerts(&AlertQueryPlan::new()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].alert_id(), alert.alert_id());
    assert_eq!(results[0].rule_id(), "shell_wrote_file_to_web_root");
    assert_eq!(results[0].reasons().len(), 1);
    assert_eq!(results[0].evidence(), &[event_id]);
}

pub fn query_alerts_filters_by_rule_id_and_time_range(s: &dyn Storage) {
    s.write_alerts(&[
        sample_alert(vec![Uuid::now_v7()], "rule_a", 1000),
        sample_alert(vec![Uuid::now_v7()], "rule_b", 5000),
        sample_alert(vec![Uuid::now_v7()], "rule_a", 9000),
    ])
    .unwrap();

    let by_rule = s
        .query_alerts(&AlertQueryPlan {
            rule_id: Some("rule_a".to_string()),
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_rule.len(), 2);

    let by_time = s
        .query_alerts(&AlertQueryPlan {
            since: Some(2000),
            until: Some(6000),
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_time.len(), 1);
    assert_eq!(by_time[0].rule_id(), "rule_b");
}

/// The File Story's "alerts citing these events" join, in one query.
pub fn query_alerts_filters_by_the_events_they_cite(s: &dyn Storage) {
    let wanted = Uuid::now_v7();
    let other = Uuid::now_v7();
    s.write_alerts(&[
        sample_alert(vec![wanted], "rule_a", 1000),
        sample_alert(vec![other], "rule_b", 2000),
    ])
    .unwrap();

    let results = s
        .query_alerts(&AlertQueryPlan {
            evidence_event_ids: vec![wanted],
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_id(), "rule_a");
}

/// One alert citing two events must be returned once, not twice, when
/// both of its events are in the filter set.
pub fn an_alert_citing_several_matching_events_is_returned_once(s: &dyn Storage) {
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    s.write_alerts(&[sample_alert(vec![a, b], "rule_a", 1000)])
        .unwrap();

    let results = s
        .query_alerts(&AlertQueryPlan {
            evidence_event_ids: vec![a, b],
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(results.len(), 1);
}

pub fn rewriting_an_alert_id_is_ignored_and_reported_as_failed(s: &dyn Storage) {
    let alert = sample_alert(vec![Uuid::now_v7()], "rule_a", 1000);
    s.write_alerts(std::slice::from_ref(&alert)).unwrap();

    let report = s.write_alerts(std::slice::from_ref(&alert)).unwrap();
    assert_eq!(report.written_count, 0);
    assert_eq!(report.failed_count, 1);
    assert_eq!(s.query_alerts(&AlertQueryPlan::new()).unwrap().len(), 1);
}

pub fn alert_rewrite_does_not_duplicate_evidence(s: &dyn Storage) {
    let evidence = Uuid::now_v7();
    let alert = sample_alert(vec![evidence], "rule_a", 1000);
    s.write_alerts(std::slice::from_ref(&alert)).unwrap();

    let report = s.write_alerts(std::slice::from_ref(&alert)).unwrap();
    assert_eq!(report.written_count, 0);
    assert_eq!(report.failed_count, 1);

    let got = s
        .query_alerts(&AlertQueryPlan {
            evidence_event_ids: vec![evidence],
            ..AlertQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].evidence(), &[evidence]);
}
