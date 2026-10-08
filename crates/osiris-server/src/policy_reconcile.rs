//! Phase 9d-3: drives each host's applied policy toward its effective policy
//! by sending signed `ApplyPolicy` commands over the 9c channel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_command::{CommandAction, CommandResult, PolicyPayload};
use osiris_fleet::{DeliveryResult, DeliveryRow, HostRegistry, PolicyStore};
use osiris_response::{CommandDispatcher, DispatchError};
use osiris_tenancy::TenantStore;
use uuid::Uuid;

pub const POLICY_RESEND_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Unmanaged,
    UnknownHost,
    InSync,
    Backoff,
    /// Another reconciliation of this host is running; it re-runs once
    /// when it finishes, so this request is not lost.
    InFlight,
    /// The agent never reported a usable policy hash (a pre-9d-3 agent, or a
    /// malformed report), so it cannot decode `ApplyPolicy`: nothing is sent.
    Unsupported,
    Sent(DeliveryResult),
}

pub struct PolicyReconciler {
    me: Weak<PolicyReconciler>,
    registry: Arc<dyn HostRegistry>,
    policies: Arc<dyn PolicyStore>,
    tenants: Arc<dyn TenantStore>,
    dispatcher: Option<Arc<dyn CommandDispatcher>>,
    /// Hosts being reconciled; the flag is set when another request for the
    /// host arrived meanwhile and the pass must run again.
    in_flight: Mutex<HashMap<Uuid, bool>>,
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Removes the host from the in-flight set however `reconcile_host` exits
/// (return, panic or cancellation) and, if another request arrived while it
/// ran, spawns one more pass so that request's desired policy is not lost.
struct InFlight<'a>(&'a PolicyReconciler, Uuid);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let dirty = self
            .0
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.1)
            .unwrap_or(false);
        // No runtime (shutdown): nothing to re-run on, and spawning would panic.
        if dirty && tokio::runtime::Handle::try_current().is_ok() {
            self.0.spawn_reconcile(vec![self.1]);
        }
    }
}

impl PolicyReconciler {
    pub fn new(
        registry: Arc<dyn HostRegistry>,
        policies: Arc<dyn PolicyStore>,
        tenants: Arc<dyn TenantStore>,
        dispatcher: Option<Arc<dyn CommandDispatcher>>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry,
            policies,
            tenants,
            dispatcher,
            in_flight: Mutex::new(HashMap::new()),
        })
    }

    pub fn spawn_reconcile(&self, hosts: Vec<Uuid>) {
        let Some(me) = self.me.upgrade() else { return };
        for host in hosts {
            let me = me.clone();
            tokio::spawn(async move {
                let outcome = me.reconcile_host(host).await;
                tracing::debug!(%host, ?outcome, "policy reconciliation");
            });
        }
    }

    pub async fn reconcile_host(&self, host_id: Uuid) -> ReconcileOutcome {
        let Some(dispatcher) = self.dispatcher.clone() else {
            return ReconcileOutcome::Unmanaged;
        };
        {
            let mut in_flight = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(dirty) = in_flight.get_mut(&host_id) {
                *dirty = true;
                return ReconcileOutcome::InFlight;
            }
            in_flight.insert(host_id, false);
        }
        let _guard = InFlight(self, host_id);

        let (registry, policies, tenants) = (
            self.registry.clone(),
            self.policies.clone(),
            self.tenants.clone(),
        );
        let gathered = tokio::task::spawn_blocking(move || -> Result<_, String> {
            let Some(row) = registry.get(host_id).map_err(|e| e.to_string())? else {
                return Ok(None);
            };
            let tenant = tenants.tenant_of(host_id).map_err(|e| e.to_string())?;
            let inputs = policies
                .policies_for_host(host_id)
                .map_err(|e| e.to_string())?;
            let delivery = policies.delivery(host_id).map_err(|e| e.to_string())?;
            Ok(Some((
                row.applied_policy_hash,
                osiris_policy::resolve(tenant, &inputs).effective,
                delivery,
            )))
        })
        .await;
        let (applied, effective, delivery) = match gathered {
            Ok(Ok(Some(v))) => v,
            Ok(Ok(None)) => return ReconcileOutcome::UnknownHost,
            Ok(Err(e)) => {
                tracing::error!(%host_id, error = %e, "policy reconciliation lookup failed");
                return ReconcileOutcome::InSync;
            }
            Err(e) => {
                tracing::error!(%host_id, error = %e, "policy reconciliation task failed");
                return ReconcileOutcome::InSync;
            }
        };
        let desired = effective.hash_hex();
        let Some(applied) = applied else {
            // No usable hash reported: the agent is pre-9d-3 (or broken) and
            // would drop its control session on an `ApplyPolicy` it cannot
            // decode. It counts as "no policy" for status, but is never sent one.
            return if desired == osiris_policy::empty_policy_hash_hex() {
                ReconcileOutcome::InSync
            } else {
                ReconcileOutcome::Unsupported
            };
        };
        if applied == desired {
            return ReconcileOutcome::InSync;
        }
        let now = now_ns();
        if delivery.is_some_and(|d| {
            d.desired_hash == desired
                && now.saturating_sub(d.last_sent_at) < POLICY_RESEND_BACKOFF.as_nanos() as u64
        }) {
            return ReconcileOutcome::Backoff;
        }
        let reply = dispatcher
            .dispatch(
                host_id,
                CommandAction::ApplyPolicy {
                    policy: PolicyPayload::from_effective(&effective),
                },
                false,
                "policy-reconciler".into(),
                format!("effective policy {}", &desired[..12]),
            )
            .await;
        let (result, error) = match reply {
            Ok(CommandResult::Executed { .. }) | Ok(CommandResult::DryRunOk { .. }) => {
                (DeliveryResult::Executed, None)
            }
            Ok(CommandResult::Refused { reason }) => {
                (DeliveryResult::Refused, Some(reason.to_string()))
            }
            Ok(CommandResult::Failed { message, .. }) => (DeliveryResult::Failed, Some(message)),
            Err(DispatchError::Offline) => (DeliveryResult::Offline, None),
            Err(DispatchError::TimedOut) => (DeliveryResult::TimedOut, None),
            Err(other) => (DeliveryResult::Failed, Some(other.to_string())),
        };
        let row = DeliveryRow {
            host_id,
            desired_hash: desired,
            last_sent_at: now,
            last_result: result,
            last_error: error,
        };
        let policies = self.policies.clone();
        match tokio::task::spawn_blocking(move || policies.record_delivery(&row)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(%host_id, error = %e, "cannot record policy delivery"),
            Err(e) => tracing::error!(%host_id, error = %e, "policy delivery record task failed"),
        }
        ReconcileOutcome::Sent(result)
    }
}

impl osiris_api::PolicyNotifier for PolicyReconciler {
    fn hosts_changed(&self, hosts: Vec<Uuid>) {
        self.spawn_reconcile(hosts);
    }

    fn managed(&self) -> bool {
        self.dispatcher.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_command::{CommandAction, CommandResult, ExecDetail};
    use osiris_fleet::{GroupScope, HostGroupStore, HostRow, SqliteHostRegistry};
    use osiris_policy::{GroupPolicy, TelemetryLevel};
    use osiris_tenancy::SqliteTenantStore;

    #[derive(Clone)]
    enum ScriptedReply {
        Result(CommandResult),
        Offline,
    }

    #[derive(Default)]
    struct Scripted {
        sent: std::sync::Mutex<Vec<(Uuid, CommandAction, String, String)>>,
        reply: std::sync::Mutex<Option<ScriptedReply>>,
        /// When set, each dispatch waits for a permit after recording itself.
        gate: std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>,
        entered: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl CommandDispatcher for Scripted {
        async fn dispatch(
            &self,
            host_id: Uuid,
            action: CommandAction,
            _dry: bool,
            actor: String,
            reason: String,
        ) -> Result<CommandResult, DispatchError> {
            self.sent
                .lock()
                .unwrap()
                .push((host_id, action, actor, reason));
            self.entered.notify_one();
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.acquire().await.unwrap().forget();
            }
            match self.reply.lock().unwrap().clone() {
                Some(ScriptedReply::Result(r)) => Ok(r),
                Some(ScriptedReply::Offline) => Err(DispatchError::Offline),
                None => Ok(CommandResult::Executed {
                    detail: ExecDetail {
                        summary: "ok".into(),
                        quarantine_id: None,
                        sha256: None,
                        signal: None,
                    },
                }),
            }
        }
    }

    struct Fx {
        _dir: tempfile::TempDir,
        db: Arc<SqliteHostRegistry>,
        dispatcher: Arc<Scripted>,
        rec: Arc<PolicyReconciler>,
        host: Uuid,
    }

    /// A 9d-3 agent that has reported "no policy".
    fn fx(managed: bool) -> Fx {
        fx_applied(managed, Some(osiris_policy::empty_policy_hash_hex()))
    }

    fn fx_applied(managed: bool, applied: Option<String>) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(SqliteHostRegistry::open(dir.path().join("hosts.db")).unwrap());
        let tenants: Arc<dyn TenantStore> =
            Arc::new(SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap());
        let host = Uuid::new_v4();
        db.upsert_heartbeat(HostRow {
            host_id: host,
            hostname: "h".into(),
            distro: "d".into(),
            kernel_version: "k".into(),
            agent_version: "0.1.0".into(),
            enrolled_at: 1,
            last_seen: 1,
            health_state: osiris_health::HealthState::Healthy,
            cloud_provider: None,
            cloud_instance_id: None,
            cloud_region: None,
            applied_policy_hash: applied,
        })
        .unwrap();
        let dispatcher = Arc::new(Scripted::default());
        let rec = PolicyReconciler::new(
            db.clone(),
            db.clone(),
            tenants,
            managed.then(|| dispatcher.clone() as Arc<dyn CommandDispatcher>),
        );
        Fx {
            _dir: dir,
            db,
            dispatcher,
            rec,
            host,
        }
    }

    fn with_policy(f: &Fx) -> String {
        let g = f.db.create(&GroupScope::Platform, None, "g").unwrap();
        f.db.add_member(&GroupScope::Platform, g.group_id, f.host)
            .unwrap();
        set_level(f, g.group_id, TelemetryLevel::Minimal)
    }

    /// Sets the group's policy to `level` only; returns the effective hash.
    fn set_level(f: &Fx, group_id: Uuid, level: TelemetryLevel) -> String {
        let p = GroupPolicy {
            telemetry_level: Some(level),
            ..Default::default()
        };
        f.db.set_policy(&GroupScope::Platform, group_id, &p, "u")
            .unwrap();
        osiris_policy::EffectivePolicy {
            telemetry_level: Some(level),
            ..Default::default()
        }
        .hash_hex()
    }

    fn sent_hashes(f: &Fx) -> Vec<String> {
        f.dispatcher
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, action, _, _)| match action {
                CommandAction::ApplyPolicy { policy } => hex::encode(policy.policy_hash),
                other => panic!("unexpected action {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn without_a_dispatcher_nothing_is_sent() {
        let f = fx(false);
        with_policy(&f);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Unmanaged
        );
    }

    #[tokio::test]
    async fn a_host_already_in_sync_gets_nothing() {
        let f = fx(true);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::InSync,
            "no policy + no applied hash"
        );
        assert!(f.dispatcher.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mismatch_sends_a_signed_apply_policy_and_records_it() {
        let f = fx(true);
        let desired = with_policy(&f);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Sent(DeliveryResult::Executed)
        );
        let sent = f.dispatcher.sent.lock().unwrap();
        let (host, action, actor, reason) = &sent[0];
        assert_eq!(*host, f.host);
        assert_eq!(actor, "policy-reconciler");
        assert_eq!(reason, &format!("effective policy {}", &desired[..12]));
        let CommandAction::ApplyPolicy { policy } = action else {
            panic!("wrong action")
        };
        assert_eq!(hex::encode(policy.policy_hash), desired);
        let d = f.db.delivery(f.host).unwrap().unwrap();
        assert_eq!(
            (d.desired_hash.as_str(), d.last_result),
            (desired.as_str(), DeliveryResult::Executed)
        );
    }

    #[tokio::test]
    async fn backoff_suppresses_resend_of_the_same_hash_within_60s() {
        let f = fx(true);
        with_policy(&f);
        *f.dispatcher.reply.lock().unwrap() = Some(ScriptedReply::Result(CommandResult::Refused {
            reason: osiris_command::Refusal::Replay,
        }));
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Sent(DeliveryResult::Refused)
        );
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Backoff
        );
        assert_eq!(f.dispatcher.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn offline_and_timeouts_are_recorded() {
        let f = fx(true);
        with_policy(&f);
        *f.dispatcher.reply.lock().unwrap() = Some(ScriptedReply::Offline);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Sent(DeliveryResult::Offline)
        );
    }

    #[tokio::test]
    async fn an_agent_that_never_reported_a_policy_hash_is_sent_nothing() {
        // Pre-9d-3 agents omit `policy_hash`; ingest stores that as None.
        let f = fx_applied(true, None);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::InSync,
            "no policy desired"
        );
        with_policy(&f);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::Unsupported
        );
        assert!(f.dispatcher.sent.lock().unwrap().is_empty());
        assert!(f.db.delivery(f.host).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_request_during_a_send_reruns_with_the_new_policy() {
        let f = fx(true);
        let g = f.db.create(&GroupScope::Platform, None, "g").unwrap();
        f.db.add_member(&GroupScope::Platform, g.group_id, f.host)
            .unwrap();
        let p1 = set_level(&f, g.group_id, TelemetryLevel::Minimal);
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *f.dispatcher.gate.lock().unwrap() = Some(gate.clone());

        let (rec, host) = (f.rec.clone(), f.host);
        let first = tokio::spawn(async move { rec.reconcile_host(host).await });
        f.dispatcher.entered.notified().await;

        // The policy changes while P1 is still in flight.
        let p2 = set_level(&f, g.group_id, TelemetryLevel::Standard);
        assert_eq!(
            f.rec.reconcile_host(f.host).await,
            ReconcileOutcome::InFlight
        );
        assert_eq!(sent_hashes(&f), vec![p1.clone()]);

        gate.add_permits(10);
        assert_eq!(
            first.await.unwrap(),
            ReconcileOutcome::Sent(DeliveryResult::Executed)
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while sent_hashes(&f).len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the dirty host is reconciled again");
        assert_eq!(sent_hashes(&f), vec![p1, p2.clone()]);
        // The re-run finishes and leaves nothing in flight or dirty.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !f.rec.in_flight.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("in-flight set drains");
        assert_eq!(f.db.delivery(f.host).unwrap().unwrap().desired_hash, p2);
        assert_eq!(sent_hashes(&f).len(), 2, "no further passes");
    }

    #[tokio::test]
    async fn an_unregistered_host_is_skipped() {
        let f = fx(true);
        assert_eq!(
            f.rec.reconcile_host(Uuid::new_v4()).await,
            ReconcileOutcome::UnknownHost
        );
    }
}
