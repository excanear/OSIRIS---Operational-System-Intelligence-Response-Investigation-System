use crate::envelope::{verify, CommandAction, SignedCommand};
use crate::replay::ReplayStore;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_TTL_MS: u64 = 120_000;
const SKEW_MS: u64 = 60_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Refusal {
    #[error("bad signature")]
    BadSignature,
    #[error("wrong host")]
    WrongHost,
    #[error("expired")]
    Expired,
    #[error("not yet valid")]
    NotYetValid,
    #[error("ttl too long")]
    TtlTooLong,
    #[error("replay")]
    Replay,
    #[error("busy")]
    Busy,
    #[error("protected target: {0}")]
    ProtectedTarget(String),
}

pub struct ProtectedTargets {
    pub agent_pid: u32,
    pub extra_pids: Vec<u32>,
    pub vault: PathBuf,
}

impl ProtectedTargets {
    pub fn check_pid(&self, pid: u32) -> Result<(), Refusal> {
        if pid == 1 || pid == self.agent_pid || self.extra_pids.contains(&pid) {
            return Err(Refusal::ProtectedTarget(format!("pid {pid}")));
        }
        Ok(())
    }

    pub fn check_path(&self, path: &str) -> Result<(), Refusal> {
        if Path::new(path).starts_with(&self.vault) {
            return Err(Refusal::ProtectedTarget(format!("path {path}")));
        }
        Ok(())
    }
}

pub struct Guard {
    pub host_id: Uuid,
    pub key: VerifyingKey,
    pub replay: ReplayStore,
    pub protected: ProtectedTargets,
}

impl Guard {
    pub fn admit(&self, sc: &SignedCommand, now_ms: u64) -> Result<(), Refusal> {
        let c = &sc.command;
        verify(sc, &self.key).map_err(|_| Refusal::BadSignature)?;
        if c.host_id != self.host_id {
            return Err(Refusal::WrongHost);
        }
        if c.expires_at_ms.saturating_sub(c.issued_at_ms) > MAX_TTL_MS {
            return Err(Refusal::TtlTooLong);
        }
        if c.issued_at_ms > now_ms.saturating_add(SKEW_MS) {
            return Err(Refusal::NotYetValid);
        }
        if now_ms >= c.expires_at_ms {
            return Err(Refusal::Expired);
        }
        self.replay
            .check_and_record(c.command_id, c.expires_at_ms, now_ms)?;
        match &c.action {
            CommandAction::TerminateProcess { pid, .. } => self.protected.check_pid(*pid),
            CommandAction::QuarantineFile { path, .. } => self.protected.check_path(path),
            CommandAction::RestoreFile { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign, Command, CommandAction, SigningKey};
    use std::path::PathBuf;
    use uuid::Uuid;

    const NOW: u64 = 1_000_000;
    const HOST: u128 = 2;

    struct Fx {
        _dir: tempfile::TempDir,
        replay_path: PathBuf,
        key: SigningKey,
        guard: Guard,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let replay_path = dir.path().join("replay.log");
        let key = crate::keys::generate_signing_key();
        let guard = Guard {
            host_id: Uuid::from_u128(HOST),
            key: key.verifying_key(),
            replay: ReplayStore::open(&replay_path).unwrap(),
            protected: ProtectedTargets {
                agent_pid: 500,
                extra_pids: vec![499],
                vault: PathBuf::from("/var/lib/osiris/vault"),
            },
        };
        Fx {
            _dir: dir,
            replay_path,
            key,
            guard,
        }
    }

    fn term(pid: u32) -> CommandAction {
        CommandAction::TerminateProcess {
            pid,
            exe_path: "/bin/x".into(),
            observed_at_ns: 5,
        }
    }

    fn signed(f: &Fx, action: CommandAction, m: impl FnOnce(&mut Command)) -> crate::SignedCommand {
        let mut c = Command {
            command_id: Uuid::new_v4(),
            host_id: Uuid::from_u128(HOST),
            action,
            dry_run: false,
            issued_at_ms: NOW,
            expires_at_ms: NOW + 30_000,
            nonce: [1u8; 16],
            actor: "a".into(),
            reason: "r".into(),
        };
        m(&mut c);
        sign(c, &f.key)
    }

    #[test]
    fn valid_command_admitted() {
        let f = fx();
        let sc = signed(&f, term(42), |_| {});
        assert_eq!(f.guard.admit(&sc, NOW), Ok(()));
    }

    #[test]
    fn bad_signature() {
        let f = fx();
        let mut sc = signed(&f, term(42), |_| {});
        sc.command.reason = "tampered".into();
        assert_eq!(f.guard.admit(&sc, NOW), Err(Refusal::BadSignature));
    }

    #[test]
    fn wrong_host() {
        let f = fx();
        let sc = signed(&f, term(42), |c| c.host_id = Uuid::from_u128(99));
        assert_eq!(f.guard.admit(&sc, NOW), Err(Refusal::WrongHost));
    }

    #[test]
    fn ttl_too_long() {
        let f = fx();
        let sc = signed(&f, term(42), |c| c.expires_at_ms = c.issued_at_ms + 121_000);
        assert_eq!(f.guard.admit(&sc, NOW), Err(Refusal::TtlTooLong));
    }

    #[test]
    fn not_yet_valid() {
        let f = fx();
        let sc = signed(&f, term(42), |c| {
            c.issued_at_ms = NOW + 61_000;
            c.expires_at_ms = NOW + 91_000;
        });
        assert_eq!(f.guard.admit(&sc, NOW), Err(Refusal::NotYetValid));
    }

    #[test]
    fn expired() {
        let f = fx();
        let sc = signed(&f, term(42), |_| {});
        assert_eq!(f.guard.admit(&sc, NOW + 30_000), Err(Refusal::Expired));
    }

    #[test]
    fn replay_refused_and_survives_restart() {
        let f = fx();
        let sc = signed(&f, term(42), |_| {});
        assert_eq!(f.guard.admit(&sc, NOW), Ok(()));
        assert_eq!(f.guard.admit(&sc, NOW), Err(Refusal::Replay));
        let reopened = ReplayStore::open(&f.replay_path).unwrap();
        assert_eq!(
            reopened.check_and_record(sc.command.command_id, NOW + 30_000, NOW),
            Err(Refusal::Replay)
        );
    }

    #[test]
    fn replay_entries_pruned_after_expiry_plus_grace() {
        let f = fx();
        let id = Uuid::new_v4();
        assert_eq!(f.guard.replay.check_and_record(id, 10_000, 0), Ok(()));
        assert_eq!(f.guard.replay.check_and_record(id, 10_000, 70_001), Ok(()));
    }

    #[test]
    fn protected_pids() {
        let f = fx();
        for pid in [1, 500, 499] {
            let sc = signed(&f, term(pid), |_| {});
            assert!(
                matches!(f.guard.admit(&sc, NOW), Err(Refusal::ProtectedTarget(_))),
                "{pid}"
            );
        }
    }

    #[test]
    fn vault_path_protected() {
        let f = fx();
        let sc = signed(
            &f,
            CommandAction::QuarantineFile {
                path: "/var/lib/osiris/vault/abc".into(),
                inode: 1,
                device_id: 1,
            },
            |_| {},
        );
        assert!(matches!(
            f.guard.admit(&sc, NOW),
            Err(Refusal::ProtectedTarget(_))
        ));
    }
}
