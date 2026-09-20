//! Server side of the command channel: signs commands and sends them to Agents
//! over the control hub (Phase 9c-1).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use osiris_command::{sign, Command, CommandAction, CommandResult, SignedCommand, SigningKey};
use osiris_response::{CommandDispatcher, DispatchError};
use osiris_transport::control::{ControlHub, SendError};
use uuid::Uuid;

pub use osiris_response::DisabledDispatcher;

/// Upper bound of a command's validity window.
const MAX_TTL_MS: u64 = 120_000;
/// Slack added on top of the wait timeout so a result racing the timeout is still valid.
const TTL_SLACK_MS: u64 = 5_000;

/// Signs commands and sends them through the [`ControlHub`].
///
/// `DispatchError::TimedOut` NEVER means "not executed": the signed validity
/// window is `timeout + 5 s`, so the Agent may still accept the command for
/// ~5 s after the server reported `TimedOut` and then run it for up to its own
/// execution timeout. An Agent clock that lags by X also extends validity by X;
/// the server cannot bound skew.
pub struct HubDispatcher {
    hub: ControlHub,
    key: SigningKey,
    timeout: Duration,
}

/// Maps a hub send failure to the dispatcher's error type.
fn map_send_error(e: SendError) -> DispatchError {
    match e {
        SendError::Offline => DispatchError::Offline,
        SendError::TimedOut => DispatchError::TimedOut,
        other @ (SendError::Disconnected | SendError::Duplicate) => {
            DispatchError::Failed(other.to_string())
        }
    }
}

impl HubDispatcher {
    pub fn new(hub: ControlHub, key: SigningKey, timeout: Duration) -> Self {
        Self { hub, key, timeout }
    }

    fn now_ms() -> Result<u64, DispatchError> {
        Self::ms_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
    }

    fn ms_since_epoch(
        d: Result<Duration, std::time::SystemTimeError>,
    ) -> Result<u64, DispatchError> {
        d.map(|d| d.as_millis() as u64)
            .map_err(|_| DispatchError::Failed("system clock before unix epoch".into()))
    }

    fn build_command(
        &self,
        now_ms: u64,
        host_id: Uuid,
        action: CommandAction,
        dry_run: bool,
        actor: String,
        reason: String,
    ) -> Command {
        // The window is timeout + 5 s (capped): TimedOut therefore does not
        // mean "not executed", and Agent clock lag extends it (see type docs).
        let ttl = (self.timeout.as_millis() as u64 + TTL_SLACK_MS).min(MAX_TTL_MS);
        Command {
            command_id: Uuid::new_v4(),
            host_id,
            action,
            dry_run,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + ttl,
            nonce: rand::random(),
            actor,
            reason,
        }
    }

    fn build(
        &self,
        host_id: Uuid,
        action: CommandAction,
        dry_run: bool,
        actor: String,
        reason: String,
    ) -> Result<SignedCommand, DispatchError> {
        let cmd = self.build_command(Self::now_ms()?, host_id, action, dry_run, actor, reason);
        Ok(sign(cmd, &self.key))
    }
}

#[async_trait]
impl CommandDispatcher for HubDispatcher {
    async fn dispatch(
        &self,
        host_id: Uuid,
        action: CommandAction,
        dry_run: bool,
        actor: String,
        reason: String,
    ) -> Result<CommandResult, DispatchError> {
        let signed = self.build(host_id, action, dry_run, actor, reason)?;
        self.hub
            .send(host_id, signed, self.timeout)
            .await
            .map_err(map_send_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{keys::generate_signing_key, verify};

    fn dispatcher(timeout: Duration) -> HubDispatcher {
        HubDispatcher::new(ControlHub::new(), generate_signing_key(), timeout)
    }

    fn action() -> CommandAction {
        CommandAction::TerminateProcess {
            pid: 1,
            exe_path: "/bin/x".into(),
            observed_at_ns: 1,
        }
    }

    #[test]
    fn builds_a_verifiable_command_for_the_right_host_with_bounded_ttl() {
        let d = dispatcher(Duration::from_secs(30));
        let host = Uuid::new_v4();
        let a = d
            .build(host, action(), true, "alice".into(), "why".into())
            .unwrap();
        verify(&a, &d.key.verifying_key()).unwrap();
        assert_eq!(a.command.host_id, host);
        assert!(a.command.dry_run);
        assert_eq!(a.command.expires_at_ms - a.command.issued_at_ms, 35_000);
        let b = d
            .build(host, action(), false, "alice".into(), "why".into())
            .unwrap();
        assert_ne!(a.command.command_id, b.command.command_id);
        assert_ne!(a.command.nonce, b.command.nonce);
    }

    #[test]
    fn ttl_is_capped_at_120_seconds() {
        let d = dispatcher(Duration::from_secs(600));
        let a = d
            .build(Uuid::new_v4(), action(), false, "a".into(), "r".into())
            .unwrap();
        assert_eq!(a.command.expires_at_ms - a.command.issued_at_ms, 120_000);
    }

    #[test]
    fn action_actor_and_reason_are_carried_into_the_signed_command() {
        let d = dispatcher(Duration::from_secs(30));
        let a = CommandAction::QuarantineFile {
            path: "/tmp/x".into(),
            inode: 7,
            device_id: 9,
        };
        let s = d
            .build(
                Uuid::new_v4(),
                a.clone(),
                true,
                "alice".into(),
                "because".into(),
            )
            .unwrap();
        verify(&s, &d.key.verifying_key()).unwrap();
        assert_eq!(s.command.action, a);
        assert_eq!(s.command.actor, "alice");
        assert_eq!(s.command.reason, "because");
    }

    #[test]
    fn send_errors_map_to_dispatch_errors() {
        assert!(matches!(
            map_send_error(SendError::Offline),
            DispatchError::Offline
        ));
        assert!(matches!(
            map_send_error(SendError::TimedOut),
            DispatchError::TimedOut
        ));
        assert!(matches!(
            map_send_error(SendError::Disconnected),
            DispatchError::Failed(_)
        ));
        assert!(matches!(
            map_send_error(SendError::Duplicate),
            DispatchError::Failed(_)
        ));
    }

    #[test]
    fn pre_epoch_clock_is_a_failure_not_zero() {
        let before = UNIX_EPOCH - Duration::from_secs(5);
        let err = HubDispatcher::ms_since_epoch(before.duration_since(UNIX_EPOCH)).unwrap_err();
        assert!(matches!(err, DispatchError::Failed(m) if m.contains("before unix epoch")));
        assert_eq!(
            HubDispatcher::ms_since_epoch(Ok(Duration::from_millis(5))).unwrap(),
            5
        );
    }

    #[tokio::test]
    async fn offline_host_maps_to_offline() {
        let d = dispatcher(Duration::from_secs(1));
        let err = d
            .dispatch(Uuid::new_v4(), action(), false, "a".into(), "r".into())
            .await
            .unwrap_err();
        assert!(matches!(err, DispatchError::Offline));
    }

    #[tokio::test]
    async fn disabled_dispatcher_reports_disabled() {
        let err = DisabledDispatcher
            .dispatch(Uuid::new_v4(), action(), false, "a".into(), "r".into())
            .await
            .unwrap_err();
        assert!(matches!(err, DispatchError::Disabled));
    }
}
