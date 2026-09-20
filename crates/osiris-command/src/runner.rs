use crate::envelope::{CommandAction, SignedCommand};
use crate::executor::{ActionExecutor, CommandResult};
use crate::guard::Guard;

pub fn run_command(
    guard: &Guard,
    exec: &dyn ActionExecutor,
    sc: &SignedCommand,
    now_ms: u64,
) -> CommandResult {
    if let Err(reason) = guard.admit(sc, now_ms) {
        return CommandResult::Refused { reason };
    }
    let dry = sc.command.dry_run;
    let res = match &sc.command.action {
        CommandAction::TerminateProcess {
            pid,
            exe_path,
            observed_at_ns,
        } => exec.terminate(*pid, exe_path, *observed_at_ns, dry),
        CommandAction::QuarantineFile {
            path,
            inode,
            device_id,
        } => exec.quarantine(path, *inode, *device_id, dry),
        CommandAction::RestoreFile { quarantine_id } => exec.restore(*quarantine_id, dry),
    };
    match res {
        Ok(detail) if dry => CommandResult::DryRunOk {
            would_do: detail.summary,
        },
        Ok(detail) => CommandResult::Executed { detail },
        Err(f) => CommandResult::Failed {
            code: f.code,
            message: f.message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sign, Command, CommandAction, FailCode, FakeExecutor, ProtectedTargets, Refusal,
        ReplayStore,
    };
    use std::path::PathBuf;
    use uuid::Uuid;

    const NOW: u64 = 1_000_000;

    fn setup() -> (tempfile::TempDir, crate::SigningKey, Guard) {
        let dir = tempfile::tempdir().unwrap();
        let key = crate::keys::generate_signing_key();
        let guard = Guard {
            host_id: Uuid::from_u128(2),
            key: key.verifying_key(),
            replay: ReplayStore::open(&dir.path().join("r")).unwrap(),
            protected: ProtectedTargets {
                agent_pid: 500,
                extra_pids: vec![],
                vault: PathBuf::from("/vault"),
            },
        };
        (dir, key, guard)
    }

    fn cmd(key: &crate::SigningKey, pid: u32, dry: bool) -> crate::SignedCommand {
        sign(
            Command {
                command_id: Uuid::new_v4(),
                host_id: Uuid::from_u128(2),
                action: CommandAction::TerminateProcess {
                    pid,
                    exe_path: "/bin/x".into(),
                    observed_at_ns: 5,
                },
                dry_run: dry,
                issued_at_ms: NOW,
                expires_at_ms: NOW + 30_000,
                nonce: [0; 16],
                actor: "a".into(),
                reason: "r".into(),
            },
            key,
        )
    }

    #[test]
    fn refusal_never_reaches_executor() {
        let (_d, key, guard) = setup();
        let ex = FakeExecutor::default();
        let r = run_command(&guard, &ex, &cmd(&key, 1, false), NOW);
        assert!(matches!(
            r,
            CommandResult::Refused {
                reason: Refusal::ProtectedTarget(_)
            }
        ));
        assert!(ex.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn valid_terminate_calls_once() {
        let (_d, key, guard) = setup();
        let ex = FakeExecutor::default();
        let r = run_command(&guard, &ex, &cmd(&key, 42, false), NOW);
        assert!(matches!(r, CommandResult::Executed { .. }));
        assert_eq!(ex.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn dry_run_returns_dry_run_ok() {
        let (_d, key, guard) = setup();
        let ex = FakeExecutor::default();
        let r = run_command(&guard, &ex, &cmd(&key, 42, true), NOW);
        assert!(matches!(r, CommandResult::DryRunOk { .. }));
        let calls = ex.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("dry_run=true"));
    }

    #[test]
    fn executor_failure_maps_to_failed() {
        let (_d, key, guard) = setup();
        let ex = FakeExecutor {
            fail_with: Some(FailCode::TargetChanged),
            ..Default::default()
        };
        let r = run_command(&guard, &ex, &cmd(&key, 42, false), NOW);
        assert!(matches!(
            r,
            CommandResult::Failed {
                code: FailCode::TargetChanged,
                ..
            }
        ));
    }
}
