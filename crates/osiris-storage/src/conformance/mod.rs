//! Backend-neutral conformance suite for the [`Storage`](crate::Storage)
//! trait. Each backend runs it from its own integration tests:
//!
//! ```ignore
//! fn fresh() -> Guard { /* empty store + whatever keeps it alive */ }
//! osiris_storage::conformance_tests!(fresh);
//! // or per group, optionally ignored:
//! osiris_storage::conformance_query_tests!(fresh, ignore = "needs a server");
//! ```
//!
//! `make_fn: fn() -> G` where `G: Deref<Target = dyn Storage>` is a guard that
//! keeps the backing resource (tempdir, test database) alive until drop and
//! hands every test a pristine, empty store.
//!
//! The groups follow the order a backend implements its tables, so a new
//! backend can turn them on one at a time: events -> query -> alerts -> graph
//! -> risk. A test lives in the group of the latest table it touches.

use osiris_schema::{
    Alert, CanonicalEvent, Category, EventType, HostRef, ProcessKey, ProcessRef, RiskScoreRecord,
    Severity, Source, WeightedReason, SCHEMA_VERSION,
};
use uuid::Uuid;

use crate::{StorageError, MAX_TENANT_HOSTS};

pub mod alerts;
pub mod events;
pub mod graph;
pub mod query;
pub mod risk;

/// A process-exec event on a fresh random host.
pub fn sample_event(pid: u32, timestamp: u64) -> CanonicalEvent {
    event_on(Uuid::new_v4(), pid, timestamp)
}

/// A process-exec event on the given host.
pub fn event_on(host: Uuid, pid: u32, timestamp: u64) -> CanonicalEvent {
    CanonicalEvent {
        event_id: Uuid::now_v7(),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id: host,
        boot_id: "b".to_string(),
        timestamp,
        monotonic_timestamp: timestamp,
        event_type: EventType::ProcessExec,
        category: Category::Process,
        severity: Severity::Info,
        host: HostRef {
            host_id: host,
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        },
        user: None,
        session: None,
        process: Some(ProcessRef {
            process_key: ProcessKey::new(host, "b", pid, timestamp),
            pid,
            exe_path: "/bin/x".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: timestamp,
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
        event_data: serde_json::json!({}),
    }
}

pub fn file_event(path: &str, inode: u64, timestamp: u64) -> CanonicalEvent {
    let mut event = sample_event(300, timestamp);
    event.event_type = EventType::FileWrite;
    event.category = Category::File;
    event.file = Some(osiris_schema::FileRef {
        path: path.to_string(),
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

pub fn network_event(src_ip: &str, dst_ip: &str, timestamp: u64) -> CanonicalEvent {
    let mut event = sample_event(300, timestamp);
    event.event_type = EventType::NetworkConnect;
    event.category = Category::Network;
    event.network = Some(osiris_schema::NetworkRef {
        src_ip: src_ip.to_string(),
        src_port: 51000,
        dst_ip: dst_ip.to_string(),
        dst_port: 443,
        proto: "tcp".to_string(),
        direction: osiris_schema::NetworkDirection::Outbound,
        bytes: None,
    });
    event
}

pub fn dns_event(query: &str, response_ips: Vec<String>, timestamp: u64) -> CanonicalEvent {
    let mut event = sample_event(300, timestamp);
    event.event_type = EventType::DnsQuery;
    event.category = Category::Dns;
    event.dns = Some(osiris_schema::DnsRef {
        query: query.to_string(),
        qtype: "A".to_string(),
        response_ips,
        ttl: Some(300),
    });
    event
}

pub fn systemd_event(unit_name: &str, timestamp: u64) -> CanonicalEvent {
    let mut event = sample_event(500, timestamp);
    event.event_type = EventType::ServiceStart;
    event.category = Category::Systemd;
    event.service = Some(osiris_schema::ServiceRef {
        unit_name: unit_name.to_string(),
        unit_type: "service".to_string(),
        action: "start".to_string(),
    });
    event
}

pub fn container_event(
    container_id: &str,
    event_type: EventType,
    timestamp: u64,
) -> CanonicalEvent {
    let mut event = sample_event(600, timestamp);
    event.event_type = event_type;
    event.category = Category::Container;
    event.container = Some(osiris_schema::ContainerRef {
        container_id: container_id.to_string(),
        image: String::new(),
        runtime: "cgroup".to_string(),
        pod_ref: None,
    });
    event
}

pub fn identity_event(
    event_type: EventType,
    session_id: &str,
    uid: u32,
    remote_addr: Option<&str>,
    timestamp: u64,
) -> CanonicalEvent {
    let mut event = sample_event(300, timestamp);
    event.event_type = event_type;
    event.category = event_type.category();
    event.session = Some(osiris_schema::SessionRef {
        session_id: session_id.to_string(),
        tty: Some("/dev/pts/0".to_string()),
        remote_addr: remote_addr.map(str::to_string),
        auth_method: Some("sshd".to_string()),
    });
    event.user = Some(osiris_schema::UserRef {
        uid,
        gid: uid,
        euid: uid,
        egid: uid,
        username: Some("alice".to_string()),
        loginuid: Some(1000),
    });
    event
}

/// An alert on a fresh random host citing `evidence`.
pub fn sample_alert(evidence: Vec<Uuid>, rule_id: &str, timestamp: u64) -> Alert {
    alert_on(Uuid::new_v4(), evidence, rule_id, timestamp)
}

pub fn alert_on(host: Uuid, evidence: Vec<Uuid>, rule_id: &str, timestamp: u64) -> Alert {
    Alert::new(
        rule_id,
        1,
        "deadbeef",
        Severity::High,
        timestamp,
        host,
        vec!["The file was written inside /var/www/".to_string()],
        evidence,
    )
    .expect("valid alert")
}

/// A risk record on a fresh random host, citing its own fresh event id.
pub fn sample_risk_record(process_key: Option<ProcessKey>, timestamp: u64) -> RiskScoreRecord {
    let event_id = Uuid::now_v7();
    RiskScoreRecord {
        event_id,
        process_key,
        host_id: Uuid::new_v4(),
        timestamp,
        score: 42,
        severity: Severity::High,
        reasons: vec![WeightedReason {
            label: "Rare executable path".to_string(),
            weight: 10,
            evidence: event_id,
        }],
        related_events: vec![event_id],
    }
}

/// `MAX_TENANT_HOSTS + 1` random host ids.
pub fn too_many_hosts() -> Vec<String> {
    (0..=MAX_TENANT_HOSTS)
        .map(|_| Uuid::new_v4().to_string())
        .collect()
}

/// Exactly `MAX_TENANT_HOSTS` host ids, one of which is `real`.
pub fn max_hosts_including(real: Uuid) -> Vec<String> {
    let mut ids: Vec<String> = (0..MAX_TENANT_HOSTS - 1)
        .map(|_| Uuid::new_v4().to_string())
        .collect();
    ids.push(real.to_string());
    ids
}

pub fn assert_too_large<T: std::fmt::Debug>(result: Result<T, StorageError>) {
    match result {
        Err(StorageError::Backend(msg)) => {
            assert!(msg.contains("tenant host set too large"), "{msg}")
        }
        other => panic!("expected the host-set-too-large error, got {other:?}"),
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_group {
    ($group:ident, $make:path, $attr:tt; $($name:ident)*) => {
        $(
            #[test]
            #$attr
            fn $name() {
                let g = $make();
                $crate::conformance::$group::$name(&*g);
            }
        )*
    };
}

/// Runs the `events` group (write, batch_write, event_owner, get_event,
/// delete, retention_apply, health) against `make_fn`.
#[macro_export]
macro_rules! conformance_events_tests {
    ($make:path) => {
        $crate::__conformance_events_cases!($make, [cfg_attr(any(), ignore)]);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::__conformance_events_cases!($make, [cfg_attr(all(), ignore = $reason)]);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_events_cases {
    ($make:path, $attr:tt) => {
        $crate::__conformance_group!(events, $make, $attr;
            write_and_get_event_round_trips
            batch_write_reports_counts
            delete_removes_events_before_cutoff
            health_reports_event_count_and_last_write
            duplicate_event_id_is_ignored_and_reported_as_failed
            get_event_returns_the_matching_event_by_id
            get_event_returns_none_for_an_unknown_id
            health_on_an_empty_store_has_no_last_write
            health_last_write_is_max_event_timestamp
            duplicate_within_one_batch_counts_once
            large_batch_write_dedupes_correctly
            write_of_a_duplicate_is_an_error
            event_owner_reports_the_host_and_none_after_delete
            delete_counts_exactly_and_rows_vanish
            retention_apply_deletes_only_older_than_max_age
        );
    };
}

/// Runs the `query` group (`query`, `query_events`) against `make_fn`.
#[macro_export]
macro_rules! conformance_query_tests {
    ($make:path) => {
        $crate::__conformance_query_cases!($make, [cfg_attr(any(), ignore)]);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::__conformance_query_cases!($make, [cfg_attr(all(), ignore = $reason)]);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_query_cases {
    ($make:path, $attr:tt) => {
        $crate::__conformance_group!(query, $make, $attr;
            write_and_query_round_trips
            query_events_with_no_filter_returns_everything_within_the_default_cap
            query_events_pushes_down_an_exact_match_event_type_filter
            query_events_pushes_down_an_exact_match_category_filter
            query_events_residual_filters_a_field_with_no_sql_pushdown
            query_events_supports_or_and_not_via_residual_evaluation
            query_events_respects_since_and_until
            query_events_clamps_to_the_effective_limit
            query_filters_by_time_range
            query_filters_by_process_key
            query_filters_by_file_path
            query_by_file_identity_spans_both_names_of_a_renamed_file
            a_process_event_with_no_file_ref_never_matches_a_file_filter
            query_filters_by_unit_name
            query_filters_by_container_id
            query_filters_by_network_addr_matching_either_src_or_dst
            query_filters_by_dns_domain
            query_filters_by_session_id_across_every_category
            query_filters_by_user_uid
            the_session_and_uid_filters_compose
            host_ids_restricts_query_and_query_events_and_empty_matches_nothing
            host_ids_combines_with_an_or_filter_that_defeats_other_pushdown
            an_oversized_host_set_is_a_clear_error_on_the_events_path
            query_events_ties_order_by_event_id_string
            full_u64_time_window_returns_everything
            empty_string_filter_does_not_match_absent_fields
            max_size_host_set_is_accepted
            hostile_strings_round_trip_and_match_exactly
            query_events_residual_rejects_never_leak
        );
    };
}

/// Runs the `alerts` group (`write_alerts`, `query_alerts`) against `make_fn`.
#[macro_export]
macro_rules! conformance_alerts_tests {
    ($make:path) => {
        $crate::__conformance_alerts_cases!($make, [cfg_attr(any(), ignore)]);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::__conformance_alerts_cases!($make, [cfg_attr(all(), ignore = $reason)]);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_alerts_cases {
    ($make:path, $attr:tt) => {
        $crate::__conformance_group!(alerts, $make, $attr;
            write_and_query_alerts_round_trips
            query_alerts_filters_by_rule_id_and_time_range
            query_alerts_filters_by_the_events_they_cite
            an_alert_citing_several_matching_events_is_returned_once
            rewriting_an_alert_id_is_ignored_and_reported_as_failed
            alert_rewrite_does_not_duplicate_evidence
        );
    };
}

/// Runs the `graph` group (`write_relationships`, `query_relationships`)
/// against `make_fn`.
#[macro_export]
macro_rules! conformance_graph_tests {
    ($make:path) => {
        $crate::__conformance_graph_cases!($make, [cfg_attr(any(), ignore)]);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::__conformance_graph_cases!($make, [cfg_attr(all(), ignore = $reason)]);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_graph_cases {
    ($make:path, $attr:tt) => {
        $crate::__conformance_group!(graph, $make, $attr;
            writing_the_same_relationship_batch_twice_is_idempotent
            write_and_query_relationships_round_trips_by_either_side_of_the_edge
            query_relationships_filters_by_time_range_and_limit
            host_ids_restricts_relationships_through_the_source_event
            an_oversized_host_set_is_a_clear_error_on_the_relationships_path
        );
    };
}

/// Runs the `risk` group (`write_risk_scores`, `query_risk_scores`, plus the
/// tests that touch every side table) against `make_fn`.
#[macro_export]
macro_rules! conformance_risk_tests {
    ($make:path) => {
        $crate::__conformance_risk_cases!($make, [cfg_attr(any(), ignore)]);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::__conformance_risk_cases!($make, [cfg_attr(all(), ignore = $reason)]);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_risk_cases {
    ($make:path, $attr:tt) => {
        $crate::__conformance_group!(risk, $make, $attr;
            write_and_query_risk_scores_round_trips_reasons_intact
            host_ids_restricts_alerts_and_risk_scores
            delete_leaves_alerts_relationships_and_risk_intact
            full_u64_time_window_on_side_tables
            max_size_host_set_on_side_tables
            risk_reasons_keep_their_written_order
        );
    };
}

/// Runs all five groups against `make_fn`; `ignore = "reason"` marks every
/// test `#[ignore]` (for backends that need an external server).
#[macro_export]
macro_rules! conformance_tests {
    ($make:path) => {
        $crate::conformance_events_tests!($make);
        $crate::conformance_query_tests!($make);
        $crate::conformance_alerts_tests!($make);
        $crate::conformance_graph_tests!($make);
        $crate::conformance_risk_tests!($make);
    };
    ($make:path, ignore = $reason:literal) => {
        $crate::conformance_events_tests!($make, ignore = $reason);
        $crate::conformance_query_tests!($make, ignore = $reason);
        $crate::conformance_alerts_tests!($make, ignore = $reason);
        $crate::conformance_graph_tests!($make, ignore = $reason);
        $crate::conformance_risk_tests!($make, ignore = $reason);
    };
}
