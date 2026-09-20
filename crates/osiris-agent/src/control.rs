//! Agent side of the Phase 9c-1 command channel: the `CommandHandler` that
//! guards and executes signed commands, and the startup wiring.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use osiris_command::{
    run_command, ActionExecutor, CommandResult, FailCode, Guard, ProtectedTargets, Refusal,
    ReplayStore, SignedCommand,
};
use osiris_transport::control::{run_control_client, CommandHandler, ControlClientConfig};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::ControlConfig;
use crate::linux_exec::{ancestors_of, default_executor};

/// One command executes at a time; up to this many more may wait.
const MAX_WAITING: usize = 8;
/// Upper bound for one command, queueing excluded.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AgentCommandHandler {
    guard: Arc<Guard>,
    executor: Arc<dyn ActionExecutor>,
    /// Commands in the system (executing + waiting); more => `Busy`.
    admission: Arc<Semaphore>,
    /// Serialises execution.
    running: Arc<Semaphore>,
    timeout: Duration,
}

impl AgentCommandHandler {
    pub fn new(guard: Guard, executor: Arc<dyn ActionExecutor>) -> Self {
        Self::with_timeout(guard, executor, COMMAND_TIMEOUT)
    }

    pub fn with_timeout(
        guard: Guard,
        executor: Arc<dyn ActionExecutor>,
        timeout: Duration,
    ) -> Self {
        Self {
            guard: Arc::new(guard),
            executor,
            admission: Arc::new(Semaphore::new(1 + MAX_WAITING)),
            running: Arc::new(Semaphore::new(1)),
            timeout,
        }
    }

    async fn execute(&self, cmd: SignedCommand) -> CommandResult {
        let Ok(admitted) = self.admission.clone().try_acquire_owned() else {
            return CommandResult::Refused {
                reason: Refusal::Busy,
            };
        };
        let Ok(run_permit) = self.running.clone().acquire_owned().await else {
            return failed("executor unavailable");
        };
        let guard = self.guard.clone();
        let executor = self.executor.clone();
        // The permits move into the blocking task, so a timed-out command that
        // is still running keeps holding the execution slot.
        let task = tokio::task::spawn_blocking(move || {
            let _admitted = admitted;
            let _run = run_permit;
            run_command(&guard, executor.as_ref(), &cmd, now_ms())
        });
        match tokio::time::timeout(self.timeout, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => failed("executor panicked"),
            Err(_) => failed("timed out"),
        }
    }
}

fn failed(message: &str) -> CommandResult {
    CommandResult::Failed {
        code: FailCode::Io,
        message: message.to_string(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[async_trait]
impl CommandHandler for AgentCommandHandler {
    async fn handle(&self, cmd: SignedCommand) -> CommandResult {
        let command_id = cmd.command.command_id;
        let result = self.execute(cmd).await;
        if let CommandResult::Refused { reason } = &result {
            // Never log the signature.
            tracing::warn!(%command_id, refusal = ?reason, "command refused");
        }
        result
    }
}

/// Creates the quarantine vault (0700 on Unix).
pub fn ensure_vault(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Starts the control task. Fails closed: an unusable key, replay file or vault
/// logs an error and starts nothing (the event forwarder is unaffected).
pub async fn start_control(
    control: &ControlConfig,
    host_id: Uuid,
    spool_path: &str,
    cancel: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let key = match osiris_command::keys::load_verifying_key(Path::new(&control.command_public_key))
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, path = %control.command_public_key,
                "command_public_key unusable; control connection NOT started");
            return None;
        }
    };
    let vault = PathBuf::from(&control.vault_dir);
    if let Err(e) = ensure_vault(&vault) {
        tracing::error!(error = %e, "cannot create quarantine vault; control connection NOT started");
        return None;
    }
    let replay = match ReplayStore::open(Path::new(&format!("{spool_path}.command_seen"))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "cannot open command replay store; control connection NOT started");
            return None;
        }
    };
    let agent_pid = std::process::id();
    let guard = Guard {
        host_id,
        key,
        replay,
        protected: ProtectedTargets {
            agent_pid,
            extra_pids: ancestors_of(agent_pid),
            vault: vault.clone(),
        },
    };
    let handler: Arc<dyn CommandHandler> =
        Arc::new(AgentCommandHandler::new(guard, default_executor(vault)));
    let cfg = ControlClientConfig {
        server_addr: control.server_addr.clone(),
        server_name: control.server_name.clone(),
        ca: PathBuf::from(&control.ca),
        cert: PathBuf::from(&control.cert),
        key: PathBuf::from(&control.key),
    };
    Some(tokio::spawn(async move {
        if let Err(e) = run_control_client(cfg, handler, cancel).await {
            tracing::error!(error = %e, "control connection not started: unusable TLS material");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{
        sign, Command, CommandAction, ExecDetail, ExecFailure, FakeExecutor, SigningKey,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    const HOST: u128 = 7;

    fn guard_for(dir: &tempfile::TempDir, key: &SigningKey) -> Guard {
        Guard {
            host_id: Uuid::from_u128(HOST),
            key: key.verifying_key(),
            replay: ReplayStore::open(&dir.path().join("seen")).unwrap(),
            protected: ProtectedTargets {
                agent_pid: 500,
                extra_pids: vec![],
                vault: dir.path().join("vault"),
            },
        }
    }

    fn setup(
        exec: Arc<dyn ActionExecutor>,
    ) -> (tempfile::TempDir, SigningKey, AgentCommandHandler) {
        let dir = tempfile::tempdir().unwrap();
        let key = osiris_command::keys::generate_signing_key();
        let h = AgentCommandHandler::new(guard_for(&dir, &key), exec);
        (dir, key, h)
    }

    fn cmd(key: &SigningKey) -> SignedCommand {
        let now = now_ms();
        sign(
            Command {
                command_id: Uuid::new_v4(),
                host_id: Uuid::from_u128(HOST),
                action: CommandAction::TerminateProcess {
                    pid: 42,
                    exe_path: "/bin/x".into(),
                    observed_at_ns: 1,
                },
                dry_run: false,
                issued_at_ms: now,
                expires_at_ms: now + 30_000,
                nonce: [3u8; 16],
                actor: "t".into(),
                reason: "t".into(),
            },
            key,
        )
    }

    #[tokio::test]
    async fn executes_then_refuses_a_repeated_command() {
        let (_d, key, h) = setup(Arc::new(FakeExecutor::default()));
        let c = cmd(&key);
        assert!(matches!(
            h.handle(c.clone()).await,
            CommandResult::Executed { .. }
        ));
        assert_eq!(
            h.handle(c).await,
            CommandResult::Refused {
                reason: Refusal::Replay
            }
        );
    }

    struct Gate {
        release: AtomicBool,
    }
    impl ActionExecutor for Gate {
        fn terminate(&self, _: u32, _: &str, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(ExecDetail {
                summary: "ok".into(),
                quarantine_id: None,
                sha256: None,
                signal: None,
            })
        }
        fn quarantine(&self, _: &str, _: u64, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
            unreachable!()
        }
        fn restore(&self, _: Uuid, _: bool) -> Result<ExecDetail, ExecFailure> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn overflow_beyond_one_running_plus_eight_waiting_is_busy() {
        let gate = Arc::new(Gate {
            release: AtomicBool::new(false),
        });
        let (_d, key, h) = setup(gate.clone());
        let h = Arc::new(h);
        let mut joins = Vec::new();
        for _ in 0..9 {
            let (h, c) = (h.clone(), cmd(&key));
            joins.push(tokio::spawn(async move { h.handle(c).await }));
        }
        // Let the nine occupy every slot while the executor blocks.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            h.handle(cmd(&key)).await,
            CommandResult::Refused {
                reason: Refusal::Busy
            }
        );
        gate.release.store(true, Ordering::SeqCst);
        for j in joins {
            assert!(matches!(j.await.unwrap(), CommandResult::Executed { .. }));
        }
    }

    struct Panics;
    impl ActionExecutor for Panics {
        fn terminate(&self, _: u32, _: &str, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
            panic!("boom")
        }
        fn quarantine(&self, _: &str, _: u64, _: u64, _: bool) -> Result<ExecDetail, ExecFailure> {
            unreachable!()
        }
        fn restore(&self, _: Uuid, _: bool) -> Result<ExecDetail, ExecFailure> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn a_panicking_executor_yields_failed_not_a_crash() {
        let (_d, key, h) = setup(Arc::new(Panics));
        assert_eq!(
            h.handle(cmd(&key)).await,
            CommandResult::Failed {
                code: FailCode::Io,
                message: "executor panicked".into()
            }
        );
    }

    #[tokio::test]
    async fn a_slow_executor_times_out() {
        let gate = Arc::new(Gate {
            release: AtomicBool::new(false),
        });
        let dir = tempfile::tempdir().unwrap();
        let key = osiris_command::keys::generate_signing_key();
        let h = AgentCommandHandler::with_timeout(
            guard_for(&dir, &key),
            gate.clone(),
            Duration::from_millis(100),
        );
        assert_eq!(
            h.handle(cmd(&key)).await,
            CommandResult::Failed {
                code: FailCode::Io,
                message: "timed out".into()
            }
        );
        gate.release.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn missing_public_key_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ControlConfig {
            server_addr: "127.0.0.1:1".into(),
            server_name: "srv".into(),
            ca: "ca".into(),
            cert: "c".into(),
            key: "k".into(),
            command_public_key: dir.path().join("nope.pub").display().to_string(),
            vault_dir: dir.path().join("vault").display().to_string(),
        };
        let spool = dir.path().join("spool").display().to_string();
        assert!(
            start_control(&cfg, Uuid::new_v4(), &spool, CancellationToken::new())
                .await
                .is_none()
        );
    }
}
