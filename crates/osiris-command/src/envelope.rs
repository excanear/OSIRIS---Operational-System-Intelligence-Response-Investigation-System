use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use osiris_policy::{EffectivePolicy, TelemetryLevel};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("bad signature")]
    BadSignature,
    #[error("io: {0}")]
    Io(String),
    #[error("bad key: {0}")]
    BadKey(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandAction {
    TerminateProcess {
        pid: u32,
        exe_path: String,
        observed_at_ns: u64,
    },
    QuarantineFile {
        path: String,
        inode: u64,
        device_id: u64,
    },
    RestoreFile {
        quarantine_id: Uuid,
    },
    ApplyPolicy {
        policy: PolicyPayload,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub telemetry_level: Option<TelemetryLevel>,
    /// Sorted by name, unique.
    pub sensors: Vec<(String, bool)>,
    pub heartbeat_interval_secs: Option<u64>,
    pub policy_hash: [u8; 32],
}

impl PolicyPayload {
    pub fn from_effective(e: &EffectivePolicy) -> Self {
        Self {
            telemetry_level: e.telemetry_level,
            sensors: e.sensors.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            heartbeat_interval_secs: e.heartbeat_interval_secs,
            policy_hash: e.hash(),
        }
    }

    /// Rebuilds the policy, rejecting anything the server could not have
    /// produced: unsorted/duplicate sensors, invalid fields, or a hash that
    /// does not match the content.
    pub fn to_effective(&self) -> Result<EffectivePolicy, String> {
        if self.sensors.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err("sensors must be sorted by name and unique".into());
        }
        let e = EffectivePolicy {
            telemetry_level: self.telemetry_level,
            sensors: self.sensors.iter().cloned().collect(),
            heartbeat_interval_secs: self.heartbeat_interval_secs,
        };
        e.validate().map_err(|err| err.to_string())?;
        if e.hash() != self.policy_hash {
            return Err("policy_hash does not match policy content".into());
        }
        Ok(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub command_id: Uuid,
    pub host_id: Uuid,
    pub action: CommandAction,
    pub dry_run: bool,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: [u8; 16],
    pub actor: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommand {
    pub command: Command,
    pub signature: Vec<u8>,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(
        &u32::try_from(s.len())
            .expect("field longer than u32::MAX")
            .to_be_bytes(),
    );
    out.extend_from_slice(s.as_bytes());
}

impl Command {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut o = b"osiris-cmd-v1\0".to_vec();
        o.extend_from_slice(self.command_id.as_bytes());
        o.extend_from_slice(self.host_id.as_bytes());
        o.push(self.dry_run as u8);
        o.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        o.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        o.extend_from_slice(&self.nonce);
        match &self.action {
            CommandAction::TerminateProcess {
                pid,
                exe_path,
                observed_at_ns,
            } => {
                o.push(1);
                o.extend_from_slice(&pid.to_be_bytes());
                put_str(&mut o, exe_path);
                o.extend_from_slice(&observed_at_ns.to_be_bytes());
            }
            CommandAction::QuarantineFile {
                path,
                inode,
                device_id,
            } => {
                o.push(2);
                put_str(&mut o, path);
                o.extend_from_slice(&inode.to_be_bytes());
                o.extend_from_slice(&device_id.to_be_bytes());
            }
            CommandAction::RestoreFile { quarantine_id } => {
                o.push(3);
                o.extend_from_slice(quarantine_id.as_bytes());
            }
            CommandAction::ApplyPolicy { policy } => {
                o.push(4);
                let sensors: Vec<(&str, bool)> = policy
                    .sensors
                    .iter()
                    .map(|(k, v)| (k.as_str(), *v))
                    .collect();
                o.extend_from_slice(&osiris_policy::encode_fields(
                    policy.telemetry_level,
                    &sensors,
                    policy.heartbeat_interval_secs,
                ));
                o.extend_from_slice(&policy.policy_hash);
            }
        }
        put_str(&mut o, &self.actor);
        put_str(&mut o, &self.reason);
        o
    }
}

pub fn sign(cmd: Command, key: &SigningKey) -> SignedCommand {
    let signature = key.sign(&cmd.canonical_bytes()).to_bytes().to_vec();
    SignedCommand {
        command: cmd,
        signature,
    }
}

pub fn verify(sc: &SignedCommand, key: &VerifyingKey) -> Result<(), CommandError> {
    let sig = Signature::from_slice(&sc.signature).map_err(|_| CommandError::BadSignature)?;
    key.verify_strict(&sc.command.canonical_bytes(), &sig)
        .map_err(|_| CommandError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(action: CommandAction) -> Command {
        Command {
            command_id: Uuid::from_u128(1),
            host_id: Uuid::from_u128(2),
            action,
            dry_run: false,
            issued_at_ms: 1_000,
            expires_at_ms: 31_000,
            nonce: [7u8; 16],
            actor: "alice".into(),
            reason: "malware".into(),
        }
    }
    fn term() -> CommandAction {
        CommandAction::TerminateProcess {
            pid: 42,
            exe_path: "/bin/x".into(),
            observed_at_ns: 5,
        }
    }
    fn policy_action() -> CommandAction {
        let mut e = osiris_policy::EffectivePolicy {
            telemetry_level: Some(osiris_policy::TelemetryLevel::Standard),
            heartbeat_interval_secs: Some(30),
            ..Default::default()
        };
        e.sensors.insert("network".into(), false);
        CommandAction::ApplyPolicy {
            policy: PolicyPayload::from_effective(&e),
        }
    }
    #[test]
    fn apply_policy_canonical_bytes_are_stable() {
        let a = sample(policy_action()).canonical_bytes();
        let b = sample(policy_action()).canonical_bytes();
        assert_eq!(a, b);
    }
    #[test]
    fn changing_any_policy_field_breaks_the_signature() {
        let key = crate::keys::generate_signing_key();
        let signed = sign(sample(policy_action()), &key);
        let mutate = |f: &dyn Fn(&mut PolicyPayload)| {
            let mut s = signed.clone();
            let CommandAction::ApplyPolicy { policy } = &mut s.command.action else {
                unreachable!()
            };
            f(policy);
            verify(&s, &key.verifying_key()).is_err()
        };
        assert!(mutate(
            &|p| p.telemetry_level = Some(osiris_policy::TelemetryLevel::Minimal)
        ));
        assert!(mutate(&|p| p.telemetry_level = None));
        assert!(mutate(&|p| p.sensors[0].1 = true));
        assert!(mutate(&|p| p.sensors.push(("filesystem".into(), false))));
        assert!(mutate(&|p| p.heartbeat_interval_secs = Some(31)));
        assert!(mutate(&|p| p.policy_hash[0] ^= 1));
        assert!(verify(&signed, &key.verifying_key()).is_ok());
    }
    #[test]
    fn to_effective_rejects_tampered_or_invalid_payloads() {
        let CommandAction::ApplyPolicy { policy } = policy_action() else {
            unreachable!()
        };
        assert!(policy.to_effective().is_ok());
        let mut bad_hash = policy.clone();
        bad_hash.heartbeat_interval_secs = Some(60);
        assert_eq!(
            bad_hash.to_effective().unwrap_err(),
            "policy_hash does not match policy content"
        );
        let mut unsorted = policy.clone();
        unsorted.sensors = vec![("network".into(), false), ("filesystem".into(), true)];
        assert_eq!(
            unsorted.to_effective().unwrap_err(),
            "sensors must be sorted by name and unique"
        );
        let mut unknown = PolicyPayload::from_effective(&Default::default());
        unknown.sensors = vec![("bogus".into(), true)];
        assert_eq!(unknown.to_effective().unwrap_err(), "unknown sensor: bogus");
        let mut with_dns = osiris_policy::EffectivePolicy::default();
        with_dns.sensors.insert("dns".into(), false);
        assert!(PolicyPayload::from_effective(&with_dns)
            .to_effective()
            .is_ok());
    }
    #[test]
    fn canonical_bytes_start_with_domain_tag_and_are_stable() {
        let b = sample(term()).canonical_bytes();
        assert!(b.starts_with(b"osiris-cmd-v1\0"));
        assert_eq!(b, sample(term()).canonical_bytes());
    }
    #[test]
    fn changing_any_field_changes_the_bytes() {
        let base = sample(term()).canonical_bytes();
        let mut c = sample(term());
        c.host_id = Uuid::from_u128(3);
        assert_ne!(base, c.canonical_bytes());
        let mut c = sample(term());
        c.dry_run = true;
        assert_ne!(base, c.canonical_bytes());
        let mut c = sample(term());
        c.expires_at_ms += 1;
        assert_ne!(base, c.canonical_bytes());
        let mut c = sample(term());
        c.nonce[0] = 0;
        assert_ne!(base, c.canonical_bytes());
        let mut c = sample(term());
        c.reason = "other".into();
        assert_ne!(base, c.canonical_bytes());
        let other = CommandAction::TerminateProcess {
            pid: 43,
            exe_path: "/bin/x".into(),
            observed_at_ns: 5,
        };
        assert_ne!(base, sample(other).canonical_bytes());
    }
    #[test]
    fn field_boundaries_are_unambiguous() {
        let mut a = sample(term());
        a.actor = "ab".into();
        a.reason = "c".into();
        let mut b = sample(term());
        b.actor = "a".into();
        b.reason = "bc".into();
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }
    #[test]
    fn sign_then_verify_roundtrips_and_tamper_fails() {
        let key = crate::keys::generate_signing_key();
        let sc = sign(sample(term()), &key);
        assert!(verify(&sc, &key.verifying_key()).is_ok());
        let mut bad = sc.clone();
        bad.command.host_id = Uuid::from_u128(9);
        assert!(matches!(
            verify(&bad, &key.verifying_key()),
            Err(CommandError::BadSignature)
        ));
        let other = crate::keys::generate_signing_key();
        assert!(matches!(
            verify(&sc, &other.verifying_key()),
            Err(CommandError::BadSignature)
        ));
        let mut short = sc.clone();
        short.signature.truncate(10);
        assert!(matches!(
            verify(&short, &key.verifying_key()),
            Err(CommandError::BadSignature)
        ));
    }
}
