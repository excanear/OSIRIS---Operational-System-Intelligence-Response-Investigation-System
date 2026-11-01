//! Conformance group `query`: `query` and `query_events` over the events
//! table (filters, ordering, limits, tenant host scoping).

use osiris_query::EventQueryPlan;
use osiris_schema::{Category, EventType};
use uuid::Uuid;

use super::{
    assert_too_large, container_event, dns_event, event_on, file_event, identity_event,
    max_hosts_including, network_event, sample_event, systemd_event, too_many_hosts,
};
use crate::{QueryPlan, Storage};

pub fn query_events_with_no_filter_returns_everything_within_the_default_cap(s: &dyn Storage) {
    for i in 0..3 {
        s.write(&sample_event(100 + i, 1000 + i as u64)).unwrap();
    }
    let events = s.query_events(&EventQueryPlan::new()).unwrap();
    assert_eq!(events.len(), 3);
}

pub fn query_events_pushes_down_an_exact_match_event_type_filter(s: &dyn Storage) {
    s.write(&sample_event(1, 100)).unwrap();
    let plan = EventQueryPlan::with_filter("event_type = \"PROCESS_EXEC\"").unwrap();
    assert_eq!(s.query_events(&plan).unwrap().len(), 1);
    let plan_miss = EventQueryPlan::with_filter("event_type = \"PROCESS_FORK\"").unwrap();
    assert_eq!(s.query_events(&plan_miss).unwrap().len(), 0);
}

pub fn query_events_pushes_down_an_exact_match_category_filter(s: &dyn Storage) {
    let mut file_event = sample_event(1, 100);
    file_event.event_type = EventType::FileWrite;
    file_event.category = Category::File;
    s.write(&file_event).unwrap();

    let plan = EventQueryPlan::with_filter("category = \"FILE\"").unwrap();
    assert_eq!(s.query_events(&plan).unwrap().len(), 1);

    let plan_miss = EventQueryPlan::with_filter("category = \"NETWORK\"").unwrap();
    assert_eq!(s.query_events(&plan_miss).unwrap().len(), 0);
}

pub fn query_events_residual_filters_a_field_with_no_sql_pushdown(s: &dyn Storage) {
    s.write(&sample_event(42, 100)).unwrap();
    s.write(&sample_event(43, 200)).unwrap();
    let plan = EventQueryPlan::with_filter("process.pid = 42").unwrap();
    let events = s.query_events(&plan).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].process.as_ref().unwrap().pid, 42);
}

pub fn query_events_supports_or_and_not_via_residual_evaluation(s: &dyn Storage) {
    s.write(&sample_event(1, 100)).unwrap();
    s.write(&sample_event(2, 200)).unwrap();
    let plan = EventQueryPlan::with_filter("process.pid = 1 OR process.pid = 2").unwrap();
    assert_eq!(s.query_events(&plan).unwrap().len(), 2);

    let plan_not = EventQueryPlan::with_filter("NOT process.pid = 1").unwrap();
    assert_eq!(s.query_events(&plan_not).unwrap().len(), 1);
}

pub fn query_events_respects_since_and_until(s: &dyn Storage) {
    s.write(&sample_event(1, 100)).unwrap();
    s.write(&sample_event(2, 500)).unwrap();
    s.write(&sample_event(3, 900)).unwrap();
    let mut plan = EventQueryPlan::new();
    plan.since = Some(200);
    plan.until = Some(600);
    let events = s.query_events(&plan).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].timestamp, 500);
}

pub fn query_events_clamps_to_the_effective_limit(s: &dyn Storage) {
    for i in 0..5 {
        s.write(&sample_event(i, i as u64)).unwrap();
    }
    let mut plan = EventQueryPlan::new();
    plan.limit = 2;
    assert_eq!(s.query_events(&plan).unwrap().len(), 2);
}

pub fn query_filters_by_time_range(s: &dyn Storage) {
    s.batch_write(&[
        sample_event(100, 1000),
        sample_event(200, 5000),
        sample_event(300, 9000),
    ])
    .unwrap();

    let mut plan = QueryPlan::new();
    plan.since = Some(2000);
    plan.until = Some(6000);
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].process.as_ref().unwrap().pid, 200);
}

pub fn query_filters_by_process_key(s: &dyn Storage) {
    let event = sample_event(100, 1000);
    let key = event.process.as_ref().unwrap().process_key;
    s.write(&event).unwrap();
    s.write(&sample_event(200, 2000)).unwrap();

    let mut plan = QueryPlan::new();
    plan.process_key = Some(key);
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
}

pub fn query_filters_by_file_path(s: &dyn Storage) {
    s.batch_write(&[
        file_event("/var/www/html/shell.php", 200001, 1000),
        file_event("/home/user/notes.txt", 300777, 2000),
    ])
    .unwrap();

    let plan = QueryPlan {
        file_path: Some("/var/www/html/shell.php".to_string()),
        ..QueryPlan::new()
    };
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].file.as_ref().unwrap().path,
        "/var/www/html/shell.php"
    );
}

/// The point of identity-based lookup: one inode, two names. A query by
/// identity must return both events, which is how a File Story follows
/// a file across a rename.
pub fn query_by_file_identity_spans_both_names_of_a_renamed_file(s: &dyn Storage) {
    s.batch_write(&[
        file_event("/var/www/html/.shell.php.tmp", 200001, 1000),
        file_event("/var/www/html/shell.php", 200001, 2000),
        file_event("/home/user/notes.txt", 300777, 3000),
    ])
    .unwrap();

    let plan = QueryPlan {
        file_identity: Some(osiris_schema::FileIdentity::new(
            200001,
            osiris_schema::encode_device_id(8, 1),
        )),
        ..QueryPlan::new()
    };
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].timestamp, 1000, "results stay time-ordered");
    assert_eq!(results[1].timestamp, 2000);
}

pub fn a_process_event_with_no_file_ref_never_matches_a_file_filter(s: &dyn Storage) {
    s.write(&sample_event(100, 1000)).unwrap();
    let plan = QueryPlan {
        file_path: Some("/var/www/html/shell.php".to_string()),
        ..QueryPlan::new()
    };
    assert!(s.query(&plan).unwrap().is_empty());
}

pub fn query_filters_by_unit_name(s: &dyn Storage) {
    let backdoor = systemd_event("backdoor.service", 1000);
    let mut backdoor_stop = systemd_event("backdoor.service", 2000);
    backdoor_stop.event_type = EventType::ServiceStop;
    let sshd = systemd_event("sshd.service", 3000);
    // An event with no service at all must never match any unit_name filter.
    let unrelated = sample_event(900, 4000);
    s.batch_write(&[
        backdoor.clone(),
        backdoor_stop.clone(),
        sshd.clone(),
        unrelated,
    ])
    .unwrap();

    let mut plan = QueryPlan::new();
    plan.unit_name = Some("backdoor.service".to_string());
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 2);
    let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
    assert!(ids.contains(&backdoor.event_id));
    assert!(ids.contains(&backdoor_stop.event_id));
    assert!(!ids.contains(&sshd.event_id));
}

pub fn query_filters_by_container_id(s: &dyn Storage) {
    let id_a = "a".repeat(64);
    let id_b = "b".repeat(64);
    let create = container_event(&id_a, EventType::ContainerCreate, 1000);
    let start = container_event(&id_a, EventType::ContainerStart, 2000);
    let other = container_event(&id_b, EventType::ContainerStart, 3000);
    // An event with no container at all must never match any container_id
    // filter.
    let unrelated = sample_event(900, 4000);
    s.batch_write(&[create.clone(), start.clone(), other.clone(), unrelated])
        .unwrap();

    let mut plan = QueryPlan::new();
    plan.container_id = Some(id_a);
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 2);
    let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
    assert!(ids.contains(&create.event_id));
    assert!(ids.contains(&start.event_id));
    assert!(!ids.contains(&other.event_id));
}

pub fn query_filters_by_network_addr_matching_either_src_or_dst(s: &dyn Storage) {
    let as_dst = network_event("10.0.0.5", "203.0.113.50", 1000);
    let as_src = network_event("203.0.113.50", "10.0.0.6", 2000);
    let unrelated = network_event("10.0.0.7", "198.51.100.1", 3000);
    s.batch_write(&[as_dst.clone(), as_src.clone(), unrelated])
        .unwrap();

    let mut plan = QueryPlan::new();
    plan.network_addr = Some("203.0.113.50".to_string());
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 2);
    let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
    assert!(ids.contains(&as_dst.event_id));
    assert!(ids.contains(&as_src.event_id));
}

pub fn query_filters_by_dns_domain(s: &dyn Storage) {
    let matching = dns_event("cdn-assets.xyz", vec!["203.0.113.50".to_string()], 1000);
    let other = dns_event("example.com", vec!["93.184.216.34".to_string()], 2000);
    s.batch_write(&[matching.clone(), other]).unwrap();

    let mut plan = QueryPlan::new();
    plan.dns_domain = Some("cdn-assets.xyz".to_string());
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, matching.event_id);
}

pub fn query_filters_by_session_id_across_every_category(s: &dyn Storage) {
    // The point of the session filter: one id returns the whole
    // multi-category chain, not just the identity events.
    let login = identity_event(EventType::SessionLogin, "3", 0, Some("198.51.100.10"), 1000);
    let escalation = identity_event(
        EventType::PrivilegeUidChange,
        "3",
        1000,
        Some("198.51.100.10"),
        2000,
    );
    let mut exec = identity_event(
        EventType::ProcessExec,
        "3",
        1000,
        Some("198.51.100.10"),
        3000,
    );
    exec.category = Category::Process;
    let other_session = identity_event(EventType::SessionLogin, "4", 0, None, 4000);
    // An event that predates any session attribution at all.
    let unattributed = sample_event(900, 5000);
    s.batch_write(&[
        login.clone(),
        escalation.clone(),
        exec.clone(),
        other_session,
        unattributed,
    ])
    .unwrap();

    let mut plan = QueryPlan::new();
    plan.session_id = Some("3".to_string());
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 3);
    let ids: Vec<_> = results.iter().map(|e| e.event_id).collect();
    assert!(ids.contains(&login.event_id));
    assert!(ids.contains(&escalation.event_id));
    assert!(ids.contains(&exec.event_id));
    // Storage returns rows time-ordered.
    assert_eq!(results[0].event_id, login.event_id);
    assert_eq!(results[2].event_id, exec.event_id);
}

pub fn query_filters_by_user_uid(s: &dyn Storage) {
    let root = identity_event(
        EventType::PrivilegeUidChange,
        "3",
        0,
        Some("198.51.100.10"),
        1000,
    );
    let alice = identity_event(
        EventType::PrivilegeUidChange,
        "3",
        1000,
        Some("198.51.100.10"),
        2000,
    );
    s.batch_write(&[root.clone(), alice.clone()]).unwrap();

    let mut plan = QueryPlan::new();
    plan.user_uid = Some(0);
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, root.event_id);

    // uid 0 must not be confused with "no user at all".
    s.write(&sample_event(901, 3000)).unwrap();
    assert_eq!(s.query(&plan).unwrap().len(), 1);
}

/// The two filters compose.
pub fn the_session_and_uid_filters_compose(s: &dyn Storage) {
    let alice_in_3 = identity_event(EventType::PrivilegeUidChange, "3", 1000, None, 1000);
    let root_in_3 = identity_event(EventType::PrivilegeUidChange, "3", 0, None, 2000);
    let alice_in_4 = identity_event(EventType::PrivilegeUidChange, "4", 1000, None, 3000);
    s.batch_write(&[alice_in_3.clone(), root_in_3, alice_in_4])
        .unwrap();

    let mut plan = QueryPlan::new();
    plan.session_id = Some("3".to_string());
    plan.user_uid = Some(1000);
    let results = s.query(&plan).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, alice_in_3.event_id);
}

pub fn host_ids_restricts_query_and_query_events_and_empty_matches_nothing(s: &dyn Storage) {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    s.batch_write(&[
        event_on(a, 1, 100),
        event_on(b, 2, 200),
        event_on(a, 3, 300),
    ])
    .unwrap();

    let only_a = s
        .query(&QueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..QueryPlan::new()
        })
        .unwrap();
    assert_eq!(only_a.len(), 2);
    assert!(only_a.iter().all(|e| e.host_id == a));

    let none = s
        .query(&QueryPlan {
            host_ids: Some(vec![]),
            ..QueryPlan::new()
        })
        .unwrap();
    assert!(
        none.is_empty(),
        "an empty host set must match nothing, not everything"
    );

    let both = s
        .query(&QueryPlan {
            host_ids: Some(vec![a.to_string(), b.to_string()]),
            ..QueryPlan::new()
        })
        .unwrap();
    assert_eq!(both.len(), 3);

    let ev_a = s
        .query_events(&EventQueryPlan {
            host_ids: Some(vec![a.to_string()]),
            ..EventQueryPlan::new()
        })
        .unwrap();
    assert_eq!(ev_a.len(), 2);
    assert!(ev_a.iter().all(|e| e.host_id == a));
    let ev_none = s
        .query_events(&EventQueryPlan {
            host_ids: Some(vec![]),
            ..EventQueryPlan::new()
        })
        .unwrap();
    assert!(ev_none.is_empty());
}

pub fn host_ids_combines_with_an_or_filter_that_defeats_other_pushdown(s: &dyn Storage) {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    s.batch_write(&[event_on(a, 1, 100), event_on(b, 2, 200)])
        .unwrap();
    let plan = EventQueryPlan {
        host_ids: Some(vec![a.to_string()]),
        ..EventQueryPlan::with_filter(
            "event_type = \"PROCESS_EXEC\" OR event_type = \"FILE_WRITE\"",
        )
        .unwrap()
    };
    let got = s.query_events(&plan).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id, a);
}

pub fn an_oversized_host_set_is_a_clear_error_on_the_events_path(s: &dyn Storage) {
    assert_too_large(s.query(&QueryPlan {
        host_ids: Some(too_many_hosts()),
        ..QueryPlan::new()
    }));
}

pub fn query_events_ties_order_by_event_id_string(s: &dyn Storage) {
    let events: Vec<_> = (0..12u32).map(|i| sample_event(i, 1000)).collect();
    s.batch_write(&events).unwrap();

    let got = s.query_events(&EventQueryPlan::new()).unwrap();
    let mut want: Vec<String> = events.iter().map(|e| e.event_id.to_string()).collect();
    want.sort();
    let got_ids: Vec<String> = got.iter().map(|e| e.event_id.to_string()).collect();
    assert_eq!(got_ids, want, "ties on timestamp order by event_id string");
}

pub fn full_u64_time_window_returns_everything(s: &dyn Storage) {
    s.batch_write(&[
        sample_event(1, 0),
        sample_event(2, 1_000),
        sample_event(3, i64::MAX as u64),
    ])
    .unwrap();

    let got = s
        .query(&QueryPlan {
            since: Some(0),
            until: Some(u64::MAX),
            ..QueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 3);

    let got = s
        .query_events(&EventQueryPlan {
            since: Some(0),
            until: Some(u64::MAX),
            ..EventQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 3);
}

pub fn empty_string_filter_does_not_match_absent_fields(s: &dyn Storage) {
    s.batch_write(&[sample_event(1, 100), sample_event(2, 200)])
        .unwrap();
    for plan in [
        QueryPlan {
            file_path: Some(String::new()),
            ..QueryPlan::new()
        },
        QueryPlan {
            dns_domain: Some(String::new()),
            ..QueryPlan::new()
        },
        QueryPlan {
            unit_name: Some(String::new()),
            ..QueryPlan::new()
        },
    ] {
        assert!(
            s.query(&plan).unwrap().is_empty(),
            "an empty-string filter must not match absent fields: {plan:?}"
        );
    }
}

pub fn max_size_host_set_is_accepted(s: &dyn Storage) {
    let real = Uuid::new_v4();
    s.batch_write(&[event_on(real, 1, 100), event_on(Uuid::new_v4(), 2, 200)])
        .unwrap();

    let got = s
        .query(&QueryPlan {
            host_ids: Some(max_hosts_including(real)),
            ..QueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id, real);

    let got = s
        .query_events(&EventQueryPlan {
            host_ids: Some(max_hosts_including(real)),
            ..EventQueryPlan::new()
        })
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].host_id, real);

    let mut over = max_hosts_including(real);
    over.push(Uuid::new_v4().to_string());
    assert_eq!(over.len(), crate::MAX_TENANT_HOSTS + 1);
    assert_too_large(s.query(&QueryPlan {
        host_ids: Some(over.clone()),
        ..QueryPlan::new()
    }));
    assert_too_large(s.query_events(&EventQueryPlan {
        host_ids: Some(over),
        ..EventQueryPlan::new()
    }));
}

pub fn hostile_strings_round_trip_and_match_exactly(s: &dyn Storage) {
    let hostile = "a'b\"c\\d\n\u{2713} \u{fc}";
    let written = file_event(hostile, 777, 1000);
    // OQL string literals have no escape syntax, so a literal containing a
    // double quote cannot be written in a query; the OQL half of this test
    // uses the same hostile string minus the quote.
    let hostile_oql = "a'bc\\d\n\u{2713} \u{fc}";
    let written_oql = file_event(hostile_oql, 778, 2000);
    s.batch_write(&[written.clone(), written_oql.clone()])
        .unwrap();

    let fetched = s.get_event(written.event_id).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&fetched).unwrap(),
        serde_json::to_value(&written).unwrap()
    );

    let by_path = s
        .query(&QueryPlan {
            file_path: Some(hostile.to_string()),
            ..QueryPlan::new()
        })
        .unwrap();
    assert_eq!(by_path.len(), 1);
    assert_eq!(by_path[0].event_id, written.event_id);

    let plan = EventQueryPlan::with_filter(&format!("file.path = \"{hostile_oql}\"")).unwrap();
    let by_oql = s.query_events(&plan).unwrap();
    assert_eq!(by_oql.len(), 1);
    assert_eq!(by_oql[0].event_id, written_oql.event_id);

    // One character off matches nothing.
    let near = format!("{hostile}x");
    assert!(s
        .query(&QueryPlan {
            file_path: Some(near),
            ..QueryPlan::new()
        })
        .unwrap()
        .is_empty());
    let near_oql = EventQueryPlan::with_filter(&format!("file.path = \"{hostile_oql}x\"")).unwrap();
    assert!(s.query_events(&near_oql).unwrap().is_empty());
}

pub fn query_events_residual_rejects_never_leak(s: &dyn Storage) {
    let events: Vec<_> = (0..50u32)
        .map(|i| sample_event(i, 1000 + i as u64))
        .collect();
    s.batch_write(&events).unwrap();

    let plan =
        EventQueryPlan::with_filter("process.pid = 7 AND event_type = \"PROCESS_EXEC\"").unwrap();
    let got = s.query_events(&plan).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].process.as_ref().unwrap().pid, 7);
    assert_eq!(got[0].event_id, events[7].event_id);
}
