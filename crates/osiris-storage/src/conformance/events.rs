//! Conformance group `events`: the event write path, ownership, point
//! lookup, delete, retention and health.

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::{event_on, sample_event};
use crate::{DeleteCriteria, RetentionPolicy, Storage};

// Rule: nothing in this group may call `query` or `query_events` (a backend
// implements those after the events table); verify through `get_event`,
// `event_owner` and `health()` only.

fn present(s: &dyn Storage, e: &osiris_schema::CanonicalEvent) -> bool {
    s.get_event(e.event_id).unwrap().is_some()
}

pub fn write_and_get_event_round_trips(s: &dyn Storage) {
    let event = sample_event(100, 1000);
    s.write(&event).unwrap();

    let got = s.get_event(event.event_id).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&got).unwrap(),
        serde_json::to_value(&event).unwrap()
    );
}

pub fn batch_write_reports_counts(s: &dyn Storage) {
    let events = vec![sample_event(100, 1000), sample_event(200, 2000)];
    let report = s.batch_write(&events).unwrap();
    assert_eq!(report.written_count, 2);
    assert_eq!(report.failed_count, 0);
}

pub fn delete_removes_events_before_cutoff(s: &dyn Storage) {
    let (old, new) = (sample_event(100, 1000), sample_event(200, 9000));
    s.batch_write(&[old.clone(), new.clone()]).unwrap();

    let deleted = s
        .delete(&DeleteCriteria {
            before_timestamp: 5000,
        })
        .unwrap();
    assert_eq!(deleted, 1);
    assert!(!present(s, &old));
    assert!(present(s, &new));
    assert_eq!(s.health().event_count, 1);
}

pub fn health_reports_event_count_and_last_write(s: &dyn Storage) {
    s.write(&sample_event(100, 1000)).unwrap();
    let health = s.health();
    assert!(health.healthy);
    assert_eq!(health.event_count, 1);
    assert_eq!(health.last_write_at, Some(1000));
}

pub fn duplicate_event_id_is_ignored_and_reported_as_failed(s: &dyn Storage) {
    let event = sample_event(100, 1000);
    s.write(&event).unwrap();

    // Second write of an event with the same event_id must be ignored and
    // reported as failed, not silently duplicated.
    let report = s.batch_write(std::slice::from_ref(&event)).unwrap();
    assert_eq!(report.written_count, 0);
    assert_eq!(report.failed_count, 1);

    assert!(present(s, &event));
    assert_eq!(s.health().event_count, 1);
}

pub fn get_event_returns_the_matching_event_by_id(s: &dyn Storage) {
    let event = sample_event(1, 100);
    let event_id = event.event_id;
    s.write(&event).unwrap();
    let found = s.get_event(event_id).unwrap();
    assert_eq!(found.unwrap().event_id, event_id);
}

pub fn get_event_returns_none_for_an_unknown_id(s: &dyn Storage) {
    assert!(s.get_event(Uuid::new_v4()).unwrap().is_none());
}

pub fn health_on_an_empty_store_has_no_last_write(s: &dyn Storage) {
    let health = s.health();
    assert!(health.healthy);
    assert_eq!(health.event_count, 0);
    assert_eq!(health.last_write_at, None);
}

pub fn health_last_write_is_max_event_timestamp(s: &dyn Storage) {
    // Written newest-first: last_write_at is the max timestamp, not the
    // timestamp of the most recent write.
    s.write(&sample_event(1, 300)).unwrap();
    s.write(&sample_event(2, 100)).unwrap();
    let health = s.health();
    assert_eq!(health.last_write_at, Some(300));
    assert_eq!(health.event_count, 2);
}

pub fn duplicate_within_one_batch_counts_once(s: &dyn Storage) {
    let e = sample_event(1, 100);
    let report = s.batch_write(&[e.clone(), e.clone()]).unwrap();
    assert_eq!(report.written_count, 1);
    assert_eq!(report.failed_count, 1);
    assert_eq!(
        s.get_event(e.event_id).unwrap().unwrap().event_id,
        e.event_id
    );
    assert_eq!(s.health().event_count, 1);
}

pub fn large_batch_write_dedupes_correctly(s: &dyn Storage) {
    let first: Vec<_> = (0..20_000u32)
        .map(|i| sample_event(i, 1000 + i as u64))
        .collect();
    let report = s.batch_write(&first).unwrap();
    assert_eq!(report.written_count, 20_000);
    assert_eq!(report.failed_count, 0);

    let mut second = first.clone();
    second.extend((0..10u32).map(|i| sample_event(i, 50_000 + i as u64)));
    let report = s.batch_write(&second).unwrap();
    assert_eq!(report.written_count, 10);
    assert_eq!(report.failed_count, 20_000);
    assert_eq!(s.health().event_count, 20_010);
}

pub fn write_of_a_duplicate_is_an_error(s: &dyn Storage) {
    let e = sample_event(1, 100);
    s.write(&e).unwrap();
    assert!(s.write(&e).is_err(), "a second write() of an id must fail");
    assert_eq!(s.health().event_count, 1);
}

pub fn event_owner_reports_the_host_and_none_after_delete(s: &dyn Storage) {
    let host = Uuid::new_v4();
    let e = event_on(host, 1, 100);
    assert_eq!(s.event_owner(e.event_id).unwrap(), None);
    s.write(&e).unwrap();
    assert_eq!(s.event_owner(e.event_id).unwrap(), Some(host));

    let deleted = s
        .delete(&DeleteCriteria {
            before_timestamp: e.timestamp + 1,
        })
        .unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(s.event_owner(e.event_id).unwrap(), None);

    // The id is free again once the row is gone.
    s.write(&e).unwrap();
    assert_eq!(s.event_owner(e.event_id).unwrap(), Some(host));
}

pub fn delete_counts_exactly_and_rows_vanish(s: &dyn Storage) {
    let (a, b, c) = (
        sample_event(1, 10),
        sample_event(2, 20),
        sample_event(3, 30),
    );
    s.batch_write(&[a.clone(), b.clone(), c.clone()]).unwrap();
    let criteria = DeleteCriteria {
        before_timestamp: 25,
    };
    assert_eq!(s.delete(&criteria).unwrap(), 2);

    assert!(!present(s, &a));
    assert!(!present(s, &b));
    assert!(present(s, &c));
    assert_eq!(s.health().event_count, 1);
    assert_eq!(s.event_owner(a.event_id).unwrap(), None);
    assert_eq!(s.event_owner(c.event_id).unwrap(), Some(c.host_id));

    assert_eq!(s.delete(&criteria).unwrap(), 0);
}

pub fn retention_apply_deletes_only_older_than_max_age(s: &dyn Storage) {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let two_hours_ns = 2 * 3600 * 1_000_000_000u64;
    let (old, fresh) = (
        sample_event(1, now_ns - two_hours_ns),
        sample_event(2, now_ns),
    );
    s.batch_write(&[old.clone(), fresh.clone()]).unwrap();

    let report = s
        .retention_apply(&RetentionPolicy { max_age_secs: 3600 })
        .unwrap();
    assert_eq!(report.deleted_count, 1);
    assert!(!present(s, &old));
    assert!(present(s, &fresh));
    assert_eq!(s.health().event_count, 1);
}
