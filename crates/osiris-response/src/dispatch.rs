use osiris_evidence::{Evidence, EvidenceIncidentLinks, EvidenceSource, Integrity};
use osiris_query::MAX_EVENT_LIMIT;
use osiris_schema::{CanonicalEvent, EntityRef};
use osiris_storage::Storage;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::query::events_for_entity;
use crate::{ResponseActionKind, ResponseOutcome, ResponseRequest};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Builds the human-readable dry-run preview for `action` against
/// `target`, using one already-matched `sample` event for the
/// entity-specific detail a bare `EntityRef` cannot carry alone (a
/// process's pid, a file's path).
fn describe_target(action: ResponseActionKind, target: &EntityRef, sample: &CanonicalEvent) -> String {
    let verb = match action {
        ResponseActionKind::TerminateProcess => "terminate process",
        ResponseActionKind::StopService => "stop service",
        ResponseActionKind::QuarantineFile => "quarantine file",
        ResponseActionKind::BlockIndicator => "block indicator",
        ResponseActionKind::IsolateNetwork => "isolate network for",
        ResponseActionKind::DisablePersistence => "disable persistence for",
        ResponseActionKind::CollectEvidence => "collect evidence for",
    };
    let target_desc = match target {
        EntityRef::Process { process_key } => format!(
            "process {} (pid {}, host {})",
            process_key.as_hex(),
            sample.process.as_ref().map(|p| p.pid).unwrap_or(0),
            sample.host_id,
        ),
        EntityRef::File { inode, device_id, .. } => format!(
            "file at inode {} device {} (path {})",
            inode,
            device_id,
            sample.file.as_ref().map(|f| f.path.clone()).unwrap_or_default(),
        ),
        EntityRef::Ip { addr } => format!("network address {addr}"),
        EntityRef::Domain { name } => format!("domain {name}"),
        EntityRef::User { uid, .. } => format!("user uid {uid}"),
        EntityRef::Container { container_id } => format!("container {container_id}"),
        EntityRef::Session { session_id } => format!("session {session_id}"),
    };
    format!("would {verb} {target_desc} — no action taken, dry run")
}

/// Runs `request` through ARCHITECTURE.md §13's pipeline. Audit writing is
/// the caller's responsibility (`osiris-api`'s handler), not this
/// function's — `dispatch` is pure domain logic, deliberately free of any
/// `AuditLog` dependency (spec §2).
pub fn dispatch(
    request: &ResponseRequest,
    storage: &dyn Storage,
    evidence_store: &dyn osiris_evidence::EvidenceStore,
    links: &dyn EvidenceIncidentLinks,
) -> Result<ResponseOutcome, crate::ResponseError> {
    if request.dry_run {
        let sample = events_for_entity(storage, &request.target, 0, u64::MAX, 1, false)?;
        let Some(sample_event) = sample.into_iter().next() else {
            return Err(crate::ResponseError::UnknownTarget(request.target.clone()));
        };
        let description = describe_target(request.action, &request.target, &sample_event);
        return Ok(ResponseOutcome::DryRunPreview { description });
    }

    if !request.action.destructive() {
        let since = request.since.unwrap_or(0);
        let until = request.until.unwrap_or(u64::MAX);
        let events = events_for_entity(storage, &request.target, since, until, 10_000, true)?;
        let serialized = serde_json::to_vec(&events).expect("CanonicalEvent always serializes");
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let hash = hex::encode(hasher.finalize());
        let integrity = Integrity { hash, immutable_since: now_secs() };
        let evidence = Evidence::new(
            EvidenceSource::EventCapture,
            now_secs(),
            integrity,
            vec![request.target.clone()],
            None,
        )?;
        let event_count = events.len();
        let truncated = event_count >= MAX_EVENT_LIMIT;
        let inserted = evidence_store.insert(evidence)?;
        if let Some(incident_id) = request.incident_id {
            links.link(incident_id, inserted.evidence_id())?;
        }
        return Ok(ResponseOutcome::EvidenceCollected {
            evidence_id: inserted.evidence_id(),
            event_count,
            truncated,
        });
    }

    Ok(ResponseOutcome::Rejected {
        reason: "Active Actions milestone not yet shipped — see ARCHITECTURE.md §13/§29".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_evidence::{EvidenceStore, SqliteEvidenceIncidentLinks, SqliteEvidenceStore};
    use osiris_schema::{Category, DnsRef, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION};
    use osiris_storage_sqlite::SqliteStorage;
    use uuid::Uuid;

    fn base_event(host_id: Uuid, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef { host_id, hostname: "h".to_string(), distro: "d".to_string(), kernel_version: "k".to_string(), cloud: None },
            user: None,
            session: None,
            process: None,
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

    struct Harness {
        _dir: tempfile::TempDir,
        storage: SqliteStorage,
        evidence: SqliteEvidenceStore,
        links: SqliteEvidenceIncidentLinks,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        Harness {
            storage: SqliteStorage::open(dir.path().join("events.db")).unwrap(),
            evidence: SqliteEvidenceStore::open(dir.path().join("evidence.db").to_str().unwrap()).unwrap(),
            links: SqliteEvidenceIncidentLinks::open(dir.path().join("links.db").to_str().unwrap()).unwrap(),
            _dir: dir,
        }
    }

    fn process_request(action: ResponseActionKind, process_key: ProcessKey, dry_run: bool) -> ResponseRequest {
        ResponseRequest {
            action,
            target: EntityRef::Process { process_key },
            reason: "investigating".to_string(),
            dry_run,
            since: None,
            until: None,
            incident_id: None,
        }
    }

    #[test]
    fn dry_run_on_a_destructive_action_returns_a_preview_and_touches_nothing() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef { process_key, pid: 42, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 1000 });
        h.storage.write(&e).unwrap();

        let req = process_request(ResponseActionKind::TerminateProcess, process_key, true);
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        match outcome {
            ResponseOutcome::DryRunPreview { description } => {
                assert!(description.contains("terminate process"));
                assert!(description.contains("pid 42"));
                assert!(description.contains("dry run"));
            }
            other => panic!("expected DryRunPreview, got {other:?}"),
        }
        assert!(h.evidence.list().unwrap().is_empty(), "dry run must not create evidence");
    }

    #[test]
    fn dry_run_against_an_unresolvable_target_is_an_error() {
        let h = harness();
        let process_key = ProcessKey::new(Uuid::new_v4(), "b", 999, 1);
        let req = process_request(ResponseActionKind::TerminateProcess, process_key, true);
        let err = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap_err();
        assert!(matches!(err, crate::ResponseError::UnknownTarget(_)));
    }

    #[test]
    fn collect_evidence_executes_and_persists_a_record() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let mut e = base_event(host_id, 1000);
        e.event_type = EventType::DnsQuery;
        e.category = Category::Dns;
        e.dns = Some(DnsRef { query: "evil.example".to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None });
        h.storage.write(&e).unwrap();

        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "evil.example".to_string() },
            reason: "collecting for incident review".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        let ResponseOutcome::EvidenceCollected { evidence_id, event_count, truncated } = outcome else {
            panic!("expected EvidenceCollected, got {outcome:?}");
        };
        let stored = h.evidence.get(evidence_id).unwrap().expect("evidence must be persisted");
        assert_eq!(stored.source(), EvidenceSource::EventCapture);
        assert!(!stored.integrity().hash.is_empty());
        assert_eq!(event_count, 1);
        assert!(!truncated);
    }

    #[test]
    fn collect_evidence_with_zero_matching_events_still_succeeds() {
        let h = harness();
        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "never-seen.example".to_string() },
            reason: "confirming absence".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        assert!(matches!(outcome, ResponseOutcome::EvidenceCollected { .. }));
    }

    #[test]
    fn collect_evidence_links_to_an_incident_when_one_is_given() {
        let h = harness();
        let incident_id = Uuid::now_v7();
        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "linked.example".to_string() },
            reason: "linking test".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: Some(incident_id),
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        let ResponseOutcome::EvidenceCollected { evidence_id, .. } = outcome else { panic!("expected EvidenceCollected") };
        assert_eq!(h.links.evidence_ids_for_incident(incident_id).unwrap(), vec![evidence_id]);
    }

    // NOTE (Fix 6): a live-threshold test that actually writes >= MAX_EVENT_LIMIT
    // (5000) events to prove `truncated` flips to `true` at the real cap is
    // impractically slow for a unit test. `truncated` is computed as
    // `event_count >= MAX_EVENT_LIMIT` directly from the already-capped
    // `events` Vec returned by `events_for_entity` (see the `CollectEvidence`
    // branch above), so the logic is a one-line comparison against a
    // constant already covered by `osiris-query`'s own `effective_limit`
    // tests (`crates/osiris-query/src/plan.rs`) proving the cap is enforced.
    // This is a deliberate scope decision, not an oversight — flagged in the
    // fix-wave report.
    #[test]
    fn evidence_collected_reports_a_small_untruncated_event_count() {
        let h = harness();
        let host_id = Uuid::new_v4();
        for i in 0..3u64 {
            let mut e = base_event(host_id, 1000 + i);
            e.event_type = EventType::DnsQuery;
            e.category = Category::Dns;
            e.dns = Some(DnsRef { query: "small-batch.example".to_string(), qtype: "A".to_string(), response_ips: vec![], ttl: None });
            h.storage.write(&e).unwrap();
        }

        let req = ResponseRequest {
            action: ResponseActionKind::CollectEvidence,
            target: EntityRef::Domain { name: "small-batch.example".to_string() },
            reason: "checking truncation flag on a small batch".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
        };
        let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
        let ResponseOutcome::EvidenceCollected { event_count, truncated, .. } = outcome else {
            panic!("expected EvidenceCollected");
        };
        assert_eq!(event_count, 3);
        assert!(!truncated);
    }

    #[test]
    fn every_destructive_action_is_rejected_when_not_a_dry_run() {
        let h = harness();
        let host_id = Uuid::new_v4();
        let process_key = ProcessKey::new(host_id, "b", 42, 1000);
        let mut e = base_event(host_id, 1000);
        e.process = Some(ProcessRef { process_key, pid: 42, exe_path: "/bin/x".to_string(), cmdline: vec![], exe_hash: None, start_time_mono: 1000 });
        h.storage.write(&e).unwrap();

        for action in [
            ResponseActionKind::TerminateProcess,
            ResponseActionKind::StopService,
            ResponseActionKind::QuarantineFile,
            ResponseActionKind::BlockIndicator,
            ResponseActionKind::IsolateNetwork,
            ResponseActionKind::DisablePersistence,
        ] {
            let req = process_request(action, process_key, false);
            let outcome = dispatch(&req, &h.storage, &h.evidence, &h.links).unwrap();
            match outcome {
                ResponseOutcome::Rejected { reason } => {
                    assert!(reason.contains("Active Actions"), "{action:?}: {reason}");
                }
                other => panic!("{action:?}: expected Rejected, got {other:?}"),
            }
        }
        assert!(h.evidence.list().unwrap().is_empty(), "no destructive action may create evidence");
    }
}
