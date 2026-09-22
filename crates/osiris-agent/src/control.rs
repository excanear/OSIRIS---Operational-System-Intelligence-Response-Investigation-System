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
        // Never log the signature: only the id and the action.
        let command_id = cmd.command.command_id;
        let action = format!("{:?}", cmd.command.action);
        let result = self.execute(cmd).await;
        match &result {
            CommandResult::Refused { reason } => {
                tracing::warn!(%command_id, refusal = ?reason, "command refused");
            }
            CommandResult::Failed { code, message } => {
                tracing::warn!(%command_id, %action, code = ?code, %message, "command failed");
            }
            CommandResult::Executed { detail } => {
                tracing::info!(%command_id, %action, summary = %detail.summary, "command executed");
            }
            CommandResult::DryRunOk { would_do } => {
                tracing::info!(%command_id, %action, %would_do, "command dry run ok");
            }
        }
        result
    }
}

/// Makes sure the quarantine vault is usable, creating it 0700 if it is
/// missing.
///
/// The Agent runs as root, so it deliberately does **not** chmod or chown a
/// directory it did not create: silently widening or narrowing an
/// operator-supplied path is worse than refusing it. A pre-existing vault is
/// only accepted when it is a real directory (not a symlink), has no group or
/// other permission bits, and is owned by the uid the Agent runs as.
pub fn ensure_vault(dir: &Path) -> std::io::Result<()> {
    let not_a_dir = || {
        std::io::Error::other(format!(
            "vault {} exists but is not a real directory",
            dir.display()
        ))
    };
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => check_vault_dir(dir, &m),
        Ok(_) => Err(not_a_dir()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
            // Re-stat rather than trust the create: another process may have
            // won the race and put something else here.
            let m = std::fs::symlink_metadata(dir)?;
            if !m.file_type().is_dir() {
                return Err(not_a_dir());
            }
            check_vault_dir(dir, &m)
        }
        Err(e) => Err(e),
    }
}

/// Ownership/permission verification for an existing vault directory.
#[cfg(unix)]
fn check_vault_dir(dir: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "vault {} has mode {mode:o}: it must not be readable or writable by group or others; \
             fix it with `chmod 0700` (the agent never changes an existing vault's mode)",
            dir.display()
        )));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid() takes no arguments and cannot fail.
        let me = unsafe { libc::geteuid() };
        if meta.uid() != me {
            return Err(std::io::Error::other(format!(
                "vault {} is owned by uid {} but the agent runs as uid {me}; \
                 fix it with `chown {me}` (the agent never changes an existing vault's owner)",
                dir.display(),
                meta.uid()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_vault_dir(_dir: &Path, _meta: &std::fs::Metadata) -> std::io::Result<()> {
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
    let protected = ProtectedTargets {
        agent_pid,
        extra_pids: ancestors_of(agent_pid),
        vault: vault.clone(),
    };
    let guard = Guard {
        host_id,
        key,
        replay,
        protected: protected.clone(),
    };
    let handler: Arc<dyn CommandHandler> = Arc::new(AgentCommandHandler::new(
        guard,
        default_executor(vault, protected),
    ));
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
        // Wait (deterministically) until the nine occupy every slot.
        while h.admission.available_permits() != 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
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

    #[cfg(unix)]
    #[test]
    fn ensure_vault_creates_0700_and_refuses_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let v = dir.path().join("v");
        ensure_vault(&v).unwrap();
        assert_eq!(
            std::fs::metadata(&v).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // An existing, correctly-owned 0700 directory is accepted as is.
        ensure_vault(&v).unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&v, &link).unwrap();
        assert!(ensure_vault(&link).is_err());
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure_vault(&file).is_err());
    }

    /// An operator-supplied vault that is group/world accessible is refused,
    /// never chmodded: the agent runs as root and must not silently narrow a
    /// directory it did not create.
    #[cfg(unix)]
    #[test]
    fn ensure_vault_refuses_a_group_accessible_existing_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let v = dir.path().join("wide");
        std::fs::create_dir(&v).unwrap();
        std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = ensure_vault(&v).unwrap_err();
        assert!(e.to_string().contains("chmod 0700"), "{e}");
        // Refused, not repaired.
        assert_eq!(
            std::fs::metadata(&v).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
}
