use osiris_command::{CommandAction, CommandResult};
use osiris_schema::{CanonicalEvent, EntityRef};
use osiris_storage::Storage;
use uuid::Uuid;

use crate::{
    events_for_entity, DispatchError, ResponseActionKind, ResponseError, ResponseOutcome,
    ResponseRequest,
};

/// Maps a request onto the host and command that realise it, using `sample`
/// (an event that resolved the target) for the fields a bare `EntityRef`
/// cannot carry. `RestoreFile` and the non-remote actions have no
/// event-derived command and yield `UnknownTarget`.
pub fn remote_action(
    request: &ResponseRequest,
    sample: &CanonicalEvent,
) -> Result<(Uuid, CommandAction), ResponseError> {
    let unknown = || ResponseError::UnknownTarget(request.target.clone());
    match (request.action, &request.target) {
        (ResponseActionKind::TerminateProcess, EntityRef::Process { .. }) => {
            let p = sample.process.as_ref().ok_or_else(unknown)?;
            Ok((
                sample.host_id,
                CommandAction::TerminateProcess {
                    pid: p.pid,
                    exe_path: p.exe_path.clone(),
                    observed_at_ns: sample.timestamp,
                },
            ))
        }
        (ResponseActionKind::QuarantineFile, EntityRef::File { .. }) => {
            let f = sample.file.as_ref().ok_or_else(unknown)?;
            let inode = f.inode.ok_or_else(unknown)?;
            let device_id = f.device_id.ok_or_else(unknown)?;
            Ok((
                sample.host_id,
                CommandAction::QuarantineFile {
                    path: f.path.clone(),
                    inode,
                    device_id,
                },
            ))
        }
        _ => Err(unknown()),
    }
}

/// Resolves `request`'s target through `storage` (tenant-scoped by the
/// caller) and builds the command from the newest matching event that
/// carries the needed `process`/`file` data.
pub fn resolve_remote_action(
    request: &ResponseRequest,
    storage: &dyn Storage,
) -> Result<(Uuid, CommandAction), ResponseError> {
    let events = events_for_entity(storage, &request.target, 0, u64::MAX, 1000, false)?;
    let mut usable: Vec<CanonicalEvent> = events
        .into_iter()
        .filter(|e| remote_action(request, e).is_ok())
        .collect();
    usable.sort_by_key(|e| e.timestamp);
    let sample = usable
        .pop()
        .ok_or_else(|| ResponseError::UnknownTarget(request.target.clone()))?;
    remote_action(request, &sample)
}

/// Translates the dispatcher's answer into a `ResponseOutcome`. `Err` is
/// reserved for transport-level dispatch failures (HTTP 502).
pub fn outcome_from_dispatch(
    result: Result<CommandResult, DispatchError>,
) -> Result<ResponseOutcome, String> {
    match result {
        Ok(CommandResult::Executed { detail }) => {
            let mut text = detail.summary.clone();
            let mut extra = Vec::new();
            if let Some(id) = detail.quarantine_id {
                extra.push(format!("quarantine_id={id}"));
            }
            if let Some(h) = &detail.sha256 {
                extra.push(format!("sha256={h}"));
            }
            if let Some(s) = &detail.signal {
                extra.push(format!("signal={s}"));
            }
            if !extra.is_empty() {
                text = format!("{text} ({})", extra.join(", "));
            }
            Ok(ResponseOutcome::Executed {
                detail: text,
                quarantine_id: detail.quarantine_id,
            })
        }
        Ok(CommandResult::Failed { code, message }) => Ok(ResponseOutcome::ExecutionFailed {
            code: format!("{code:?}"),
            message,
        }),
        Ok(CommandResult::Refused { reason }) => Ok(ResponseOutcome::Refused {
            reason: reason.to_string(),
        }),
        Ok(CommandResult::DryRunOk { would_do }) => Ok(ResponseOutcome::DryRunPreview {
            description: would_do,
        }),
        Err(DispatchError::TimedOut) => Ok(ResponseOutcome::TimedOut),
        Err(DispatchError::Offline) => Ok(ResponseOutcome::AgentOffline),
        Err(DispatchError::Disabled) => Ok(ResponseOutcome::ControlDisabled),
        Err(DispatchError::Failed(m)) => Err(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DispatchError, ResponseActionKind, ResponseError, ResponseOutcome, ResponseRequest,
    };
    use osiris_command::{CommandAction, CommandResult, ExecDetail, FailCode, Refusal};
    use osiris_schema::{
        CanonicalEvent, Category, EntityRef, EventType, FileRef, HostRef, ProcessKey, ProcessRef,
        Severity, Source, SCHEMA_VERSION,
    };
    use osiris_storage::Storage;
    use uuid::Uuid;

    fn event(host_id: Uuid, ts: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: ts,
            monotonic_timestamp: ts,
            event_type: EventType::ProcessExec,
            category: Category::Process,
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

    fn req(action: ResponseActionKind, target: EntityRef) -> ResponseRequest {
        ResponseRequest {
            action,
            target,
            reason: "r".to_string(),
            dry_run: false,
            since: None,
            until: None,
            incident_id: None,
            tenant_id: None,
        }
    }

    fn with_process(host: Uuid, ts: u64, pid: u32) -> (CanonicalEvent, ProcessKey) {
        let key = ProcessKey::new(host, "b", pid, 5);
        let mut e = event(host, ts);
        e.process = Some(ProcessRef {
            process_key: key,
            pid,
            exe_path: "/bin/evil".to_string(),
            cmdline: vec![],
            exe_hash: None,
            start_time_mono: 5,
        });
        (e, key)
    }

    #[test]
    fn restore_file_is_a_destructive_wire_action() {
        assert!(ResponseActionKind::RestoreFile.destructive());
        assert_eq!(ResponseActionKind::RestoreFile.wire_form(), "RESTORE_FILE");
        assert_eq!(
            serde_json::to_string(&ResponseActionKind::RestoreFile).unwrap(),
            "\"RESTORE_FILE\""
        );
    }

    #[test]
    fn terminate_maps_to_the_event_host_pid_exe_and_timestamp() {
        let host = Uuid::new_v4();
        let (e, key) = with_process(host, 777, 42);
        let r = req(
            ResponseActionKind::TerminateProcess,
            EntityRef::Process { process_key: key },
        );
        let (h, a) = remote_action(&r, &e).unwrap();
        assert_eq!(h, host);
        assert_eq!(
            a,
            CommandAction::TerminateProcess {
                pid: 42,
                exe_path: "/bin/evil".to_string(),
                observed_at_ns: 777
            }
        );
    }

    #[test]
    fn quarantine_maps_path_inode_and_device() {
        let host = Uuid::new_v4();
        let mut e = event(host, 1);
        e.file = Some(FileRef {
            path: "/tmp/x".to_string(),
            previous_path: None,
            inode: Some(9),
            device_id: Some(3),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        let r = req(
            ResponseActionKind::QuarantineFile,
            EntityRef::File {
                host_id: host,
                inode: 9,
                device_id: 3,
            },
        );
        let (h, a) = remote_action(&r, &e).unwrap();
        assert_eq!(h, host);
        assert_eq!(
            a,
            CommandAction::QuarantineFile {
                path: "/tmp/x".to_string(),
                inode: 9,
                device_id: 3
            }
        );
    }

    #[test]
    fn a_sample_without_the_needed_field_is_unknown_target() {
        let host = Uuid::new_v4();
        let e = event(host, 1);
        let r = req(
            ResponseActionKind::TerminateProcess,
            EntityRef::Process {
                process_key: ProcessKey::new(host, "b", 1, 1),
            },
        );
        assert!(matches!(
            remote_action(&r, &e),
            Err(ResponseError::UnknownTarget(_))
        ));
        let r = req(
            ResponseActionKind::CollectEvidence,
            EntityRef::Domain {
                name: "x".to_string(),
            },
        );
        assert!(matches!(
            remote_action(&r, &e),
            Err(ResponseError::UnknownTarget(_))
        ));
    }

    #[test]
    fn resolve_picks_the_newest_event_that_carries_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let storage = osiris_storage_sqlite::SqliteStorage::open(dir.path().join("e.db")).unwrap();
        let host = Uuid::new_v4();
        let (old, key) = with_process(host, 100, 42);
        let (mut new, _) = with_process(host, 200, 42);
        new.process.as_mut().unwrap().exe_path = "/bin/newer".to_string();
        storage.write(&old).unwrap();
        storage.write(&new).unwrap();
        let r = req(
            ResponseActionKind::TerminateProcess,
            EntityRef::Process { process_key: key },
        );
        let (_, a) = resolve_remote_action(&r, &storage).unwrap();
        assert_eq!(
            a,
            CommandAction::TerminateProcess {
                pid: 42,
                exe_path: "/bin/newer".to_string(),
                observed_at_ns: 200
            }
        );
    }

    #[test]
    fn dispatch_results_map_to_outcomes() {
        let id = Uuid::new_v4();
        let ok = outcome_from_dispatch(Ok(CommandResult::Executed {
            detail: ExecDetail {
                summary: "killed".to_string(),
                quarantine_id: Some(id),
                sha256: Some("ab".to_string()),
                signal: Some("SIGKILL".to_string()),
            },
        }))
        .unwrap();
        match ok {
            ResponseOutcome::Executed {
                detail,
                quarantine_id,
            } => {
                assert_eq!(quarantine_id, Some(id));
                assert!(detail.contains("killed") && detail.contains("sha256=ab"));
                assert!(detail.contains("signal=SIGKILL"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            outcome_from_dispatch(Ok(CommandResult::Failed {
                code: FailCode::TargetChanged,
                message: "m".to_string()
            }))
            .unwrap(),
            ResponseOutcome::ExecutionFailed { code, .. } if code == "TargetChanged"
        ));
        assert!(matches!(
            outcome_from_dispatch(Ok(CommandResult::Refused {
                reason: Refusal::Replay
            }))
            .unwrap(),
            ResponseOutcome::Refused { .. }
        ));
        assert_eq!(
            outcome_from_dispatch(Err(DispatchError::TimedOut)).unwrap(),
            ResponseOutcome::TimedOut
        );
        assert_eq!(
            outcome_from_dispatch(Err(DispatchError::Offline)).unwrap(),
            ResponseOutcome::AgentOffline
        );
        assert_eq!(
            outcome_from_dispatch(Err(DispatchError::Disabled)).unwrap(),
            ResponseOutcome::ControlDisabled
        );
        assert!(outcome_from_dispatch(Err(DispatchError::Failed("x".into()))).is_err());
    }
}
