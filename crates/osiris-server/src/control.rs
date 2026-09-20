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

pub struct HubDispatcher {
    pub hub: ControlHub,
    pub key: SigningKey,
    pub timeout: Duration,
}

impl HubDispatcher {
    fn build(
        &self,
        host_id: Uuid,
        action: CommandAction,
        dry_run: bool,
        actor: String,
        reason: String,
    ) -> SignedCommand {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let ttl = (self.timeout.as_millis() as u64 + TTL_SLACK_MS).min(MAX_TTL_MS);
        let cmd = Command {
            command_id: Uuid::new_v4(),
            host_id,
            action,
            dry_run,
            issued_at_ms: now,
            expires_at_ms: now + ttl,
            nonce: rand::random(),
            actor,
            reason,
        };
        sign(cmd, &self.key)
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
        let signed = self.build(host_id, action, dry_run, actor, reason);
        self.hub
            .send(host_id, signed, self.timeout)
            .await
            .map_err(|e| match e {
                SendError::Offline => DispatchError::Offline,
                SendError::TimedOut => DispatchError::TimedOut,
                other @ (SendError::Disconnected | SendError::Duplicate) => {
                    DispatchError::Failed(other.to_string())
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{keys::generate_signing_key, verify};

    fn dispatcher(timeout: Duration) -> HubDispatcher {
        HubDispatcher {
            hub: ControlHub::new(),
            key: generate_signing_key(),
            timeout,
        }
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
        let a = d.build(host, action(), true, "alice".into(), "why".into());
        verify(&a, &d.key.verifying_key()).unwrap();
        assert_eq!(a.command.host_id, host);
        assert!(a.command.dry_run);
        assert_eq!(a.command.expires_at_ms - a.command.issued_at_ms, 35_000);
        let b = d.build(host, action(), false, "alice".into(), "why".into());
        assert_ne!(a.command.command_id, b.command.command_id);
        assert_ne!(a.command.nonce, b.command.nonce);
    }

    #[test]
    fn ttl_is_capped_at_120_seconds() {
        let d = dispatcher(Duration::from_secs(600));
        let a = d.build(Uuid::new_v4(), action(), false, "a".into(), "r".into());
        assert_eq!(a.command.expires_at_ms - a.command.issued_at_ms, 120_000);
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
