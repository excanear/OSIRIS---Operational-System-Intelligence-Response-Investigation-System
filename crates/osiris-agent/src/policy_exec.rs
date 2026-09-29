//! Phase 9d-3: the agent executor for `ApplyPolicy`. Wraps the OS-level
//! executor (terminate/quarantine/restore are delegated unchanged) so the
//! Linux-only executor needs no policy code.

use std::sync::{Arc, Weak};

use osiris_command::{ActionExecutor, ExecDetail, ExecFailure, FailCode, PolicyPayload};
use osiris_policy::EffectivePolicy;
use uuid::Uuid;

use crate::agent::Agent;

pub struct PolicyAwareExecutor {
    inner: Arc<dyn ActionExecutor>,
    agent: Weak<Agent>,
    runtime: tokio::runtime::Handle,
}

impl PolicyAwareExecutor {
    pub fn new(
        inner: Arc<dyn ActionExecutor>,
        agent: Weak<Agent>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            inner,
            agent,
            runtime,
        }
    }
}

fn level_str(p: &EffectivePolicy) -> String {
    p.telemetry_level
        .map_or("unset".into(), |l| format!("{l:?}").to_uppercase())
}

pub fn describe_diff(current: &EffectivePolicy, next: &EffectivePolicy) -> String {
    let mut parts = Vec::new();
    if current.telemetry_level != next.telemetry_level {
        parts.push(format!(
            "level {} -> {}",
            level_str(current),
            level_str(next)
        ));
    }
    let show = |v: Option<&bool>| v.map_or("unset", |e| if *e { "on" } else { "off" });
    for name in osiris_policy::KNOWN_SENSORS {
        let (a, b) = (current.sensors.get(name), next.sensors.get(name));
        if a != b {
            parts.push(format!("{name} {} -> {}", show(a), show(b)));
        }
    }
    if current.heartbeat_interval_secs != next.heartbeat_interval_secs {
        let show = |v: Option<u64>| v.map_or("unset".to_string(), |s| format!("{s}s"));
        parts.push(format!(
            "heartbeat {} -> {}",
            show(current.heartbeat_interval_secs),
            show(next.heartbeat_interval_secs)
        ));
    }
    if parts.is_empty() {
        "no change".into()
    } else {
        parts.join("; ")
    }
}

fn fail(code: FailCode, message: impl Into<String>) -> ExecFailure {
    ExecFailure {
        code,
        message: message.into(),
    }
}

impl ActionExecutor for PolicyAwareExecutor {
    fn terminate(
        &self,
        pid: u32,
        exe_path: &str,
        observed_at_ns: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.inner.terminate(pid, exe_path, observed_at_ns, dry_run)
    }

    fn quarantine(
        &self,
        path: &str,
        inode: u64,
        device_id: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.inner.quarantine(path, inode, device_id, dry_run)
    }

    fn restore(&self, id: Uuid, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.inner.restore(id, dry_run)
    }

    fn apply_policy(
        &self,
        payload: &PolicyPayload,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        let next = payload
            .to_effective()
            .map_err(|m| fail(FailCode::InvalidRequest, m))?;
        let agent = self
            .agent
            .upgrade()
            .ok_or_else(|| fail(FailCode::Io, "agent is shutting down"))?;
        let detail = |summary: String| ExecDetail {
            summary,
            quarantine_id: None,
            sha256: None,
            signal: None,
        };
        if dry_run {
            return Ok(detail(format!(
                "would apply: {}",
                describe_diff(&agent.policy().applied(), &next)
            )));
        }
        crate::policy::save_overlay(agent.overlay_path(), &next)
            .map_err(|e| fail(FailCode::Io, format!("cannot persist policy: {e}")))?;
        let summary = self.runtime.block_on(agent.apply_policy(&next));
        Ok(detail(summary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{FailCode, FakeExecutor, PolicyPayload};
    use osiris_policy::{EffectivePolicy, TelemetryLevel};

    async fn agent_in(dir: &tempfile::TempDir) -> Arc<Agent> {
        let config = crate::agent::tests::base_config(dir);
        Agent::start(config, crate::agent::tests::test_host(), "boot".into())
            .await
            .unwrap()
    }

    fn minimal() -> EffectivePolicy {
        EffectivePolicy {
            telemetry_level: Some(TelemetryLevel::Minimal),
            heartbeat_interval_secs: Some(20),
            ..Default::default()
        }
    }

    fn executor(agent: &Arc<Agent>) -> PolicyAwareExecutor {
        PolicyAwareExecutor::new(
            Arc::new(FakeExecutor::default()),
            Arc::downgrade(agent),
            tokio::runtime::Handle::current(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn apply_persists_then_applies_live() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = executor(&agent);
        let payload = PolicyPayload::from_effective(&minimal());
        let detail = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, false))
            .await
            .unwrap()
            .unwrap();
        assert!(
            detail.summary.contains("level MINIMAL"),
            "{}",
            detail.summary
        );
        assert_eq!(
            crate::policy::load_overlay(agent.overlay_path()),
            Some(minimal())
        );
        assert_eq!(agent.policy().applied(), minimal());
        agent.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dry_run_describes_the_diff_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = executor(&agent);
        let payload = PolicyPayload::from_effective(&minimal());
        let detail = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, true))
            .await
            .unwrap()
            .unwrap();
        assert!(
            detail.summary.starts_with("would apply: "),
            "{}",
            detail.summary
        );
        assert!(
            detail.summary.contains("level unset -> MINIMAL"),
            "{}",
            detail.summary
        );
        assert_eq!(crate::policy::load_overlay(agent.overlay_path()), None);
        assert!(agent.policy().applied().is_empty());
        agent.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_payload_whose_hash_does_not_match_is_refused_without_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let agent = agent_in(&dir).await;
        let exec = executor(&agent);
        let mut payload = PolicyPayload::from_effective(&minimal());
        payload.telemetry_level = Some(TelemetryLevel::Forensic);
        let err = tokio::task::spawn_blocking(move || exec.apply_policy(&payload, false))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, FailCode::InvalidRequest);
        assert_eq!(crate::policy::load_overlay(agent.overlay_path()), None);
        assert!(agent.policy().applied().is_empty());
        agent.shutdown().await;
    }

    #[test]
    fn other_actions_are_delegated() {
        let inner = Arc::new(FakeExecutor::default());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let exec =
            PolicyAwareExecutor::new(inner.clone(), std::sync::Weak::new(), rt.handle().clone());
        exec.terminate(42, "/bin/x", 5, true).unwrap();
        assert_eq!(inner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn describe_diff_lists_each_change() {
        let mut next = minimal();
        next.sensors.insert("network".into(), false);
        let d = describe_diff(&EffectivePolicy::default(), &next);
        assert!(d.contains("level unset -> MINIMAL"));
        assert!(d.contains("network unset -> off"));
        assert!(d.contains("heartbeat unset -> 20s"));
        assert_eq!(describe_diff(&next, &next), "no change");
    }
}
