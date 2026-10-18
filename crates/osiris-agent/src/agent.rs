use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_bus::{run_drain_loop, EventBus, Sink, SpoolFileSink};
use osiris_generator::{
    container_deploy_in_remote_session_scenario, exec_chain_scenario, network_beacon_scenario,
    network_download_then_write_scenario, persistence_via_systemd_service_scenario,
    ssh_sudo_escalation_scenario, web_shell_drop_scenario, SyntheticSensor,
};
use osiris_pipeline::Pipeline;
use osiris_policy::EffectivePolicy;
use osiris_schema::HostRef;
use osiris_selftelemetry::MetricsRegistry;
use osiris_sensor_api::{RawEvent, Sensor, SensorContext, SensorHealth};
use osiris_sensors_container::ContainerSensor;
use osiris_sensors_dns::sensor::DnsSensor;
use osiris_sensors_fs::FilesystemSensor;
use osiris_sensors_identity::IdentitySensor;
use osiris_sensors_net::NetworkSensor;
use osiris_sensors_persistence::PersistenceSensor;
use osiris_sensors_process::ProcessExecSensor;
use osiris_sensors_systemd::SystemdSensor;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::AgentConfig;
use crate::lifecycle::AgentLifecycle;
use crate::policy::{self, PolicyRuntime};
use crate::status::{AgentStatus, SkippedSensor};

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("failed to open spool file: {0}")]
    Spool(#[from] osiris_bus::SinkError),
    #[error("failed to bind status endpoint: {0}")]
    Status(std::io::Error),
}

/// The Agent Supervisor (ARCHITECTURE.md §3.1/§3.2), Phase 1/2 scope: starts
/// every registered sensor whose capabilities() report support, wires
/// their shared output channel through one Pipeline instance into the
/// Event Bus, and serves a local status endpoint. Plan Global Constraints
/// #11: this performs one-shot startup supervision (skip-if-unsupported,
/// aggregate health) but not runtime crash-restart-with-backoff.
pub struct Agent {
    lifecycle: Mutex<AgentLifecycle>,
    sensors: tokio::sync::Mutex<Vec<Box<dyn Sensor>>>,
    skipped_sensors: Mutex<Vec<SkippedSensor>>,
    cancellation: CancellationToken,
    /// JoinHandles for the drain-loop task and the pipeline (raw-event
    /// consumer) task, retained (rather than discarded, as `tokio::spawn`
    /// would otherwise let happen) so `shutdown()` can await them and
    /// guarantee the final drain pass (finding 3) has actually completed —
    /// and therefore that whatever was queued in the bus lanes / raw
    /// channel at shutdown time has been flushed to the sink — before
    /// `shutdown()` returns. `Option` because `JoinHandle` isn't `Clone`
    /// and shutdown only ever runs once; a `tokio::sync::Mutex` because
    /// `shutdown` takes `&self`.
    background_tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    config: AgentConfig,
    /// Kept for sensors started later by policy.
    raw_tx: mpsc::Sender<RawEvent>,
    policy: Arc<PolicyRuntime>,
    overlay_path: PathBuf,
    /// Serialises `apply_policy` so concurrent ApplyPolicy commands cannot
    /// interleave sensor toggles (and double-start a sensor).
    apply_lock: tokio::sync::Mutex<()>,
}

const DISABLED_BY_POLICY: &str = "disabled by policy";

/// Startup order of the policy-controllable sensors (the synthetic sensor
/// follows and is not policy-controlled).
const STARTUP_ORDER: [&str; 8] = [
    "process_exec",
    "filesystem",
    "network",
    "identity",
    "systemd",
    "persistence",
    "container",
    "dns",
];

/// Outcome of switching one sensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensorChange {
    Started,
    Stopped,
    Unchanged,
    NotConfigured,
    Failed(String),
}

/// Builds one sensor by name; `None` when agent.yaml does not configure it.
fn build_sensor(config: &AgentConfig, name: &str) -> Option<Box<dyn Sensor>> {
    match name {
        "process_exec" => config
            .audit_log_path
            .clone()
            .map(|p| Box::new(ProcessExecSensor::new(Some(p.into()), None)) as Box<dyn Sensor>),
        "filesystem" => config
            .fs_audit_log_path
            .clone()
            .map(|p| Box::new(FilesystemSensor::new(p)) as Box<dyn Sensor>),
        "network" => config
            .network_proc_root
            .clone()
            .map(|p| Box::new(NetworkSensor::new(p)) as Box<dyn Sensor>),
        "identity" => config
            .identity_audit_log_path
            .clone()
            .map(|p| Box::new(IdentitySensor::new(p)) as Box<dyn Sensor>),
        "systemd" => config
            .systemd_audit_log_path
            .clone()
            .map(|p| Box::new(SystemdSensor::new(p)) as Box<dyn Sensor>),
        "persistence" => (!config.persistence_watch_paths.is_empty()).then(|| {
            Box::new(PersistenceSensor::new(
                config.persistence_watch_paths.clone(),
            )) as Box<dyn Sensor>
        }),
        "container" => (!config.container_cgroup_roots.is_empty()).then(|| {
            Box::new(ContainerSensor::new(config.container_cgroup_roots.clone())) as Box<dyn Sensor>
        }),
        // Reuses `config.proc_root` (same /proc root as the resolver) for /proc/net/udp attribution.
        "dns" => config.dns_capture.as_ref().map(|c| {
            let proc_root = config.proc_root.as_deref().unwrap_or("/proc");
            Box::new(DnsSensor::new(
                PathBuf::from(proc_root),
                c.interface.clone(),
            )) as Box<dyn Sensor>
        }),
        _ => None,
    }
}

/// Capability check, initialize and start; a sensor that cannot run is
/// reported as skipped with its reason. `cancellation` is the agent-wide
/// token; the sensor receives a child of it.
async fn start_sensor(
    mut sensor: Box<dyn Sensor>,
    raw_tx: mpsc::Sender<RawEvent>,
    cancellation: CancellationToken,
) -> Result<Box<dyn Sensor>, SkippedSensor> {
    let caps = sensor.capabilities();
    if !caps.supported() {
        let reason = caps
            .unsupported_reason
            .unwrap_or_else(|| "unsupported".to_string());
        tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: unsupported on this host");
        return Err(SkippedSensor {
            name: sensor.name().to_string(),
            reason,
        });
    }
    // Each sensor gets its own child token: agent shutdown still reaches it,
    // but the sensor's `stop()` (which cancels its token) stops only that
    // sensor, and a policy restart gets a fresh, uncancelled child.
    let ctx = SensorContext::new(raw_tx, cancellation.child_token());
    if let Err(e) = sensor.initialize(ctx).await {
        let reason = e.to_string();
        tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: failed to initialize");
        return Err(SkippedSensor {
            name: sensor.name().to_string(),
            reason,
        });
    }
    if let Err(e) = sensor.start().await {
        let reason = format!("start failed: {e}");
        tracing::warn!(sensor = sensor.name(), reason = %reason, "skipping sensor: failed to start");
        return Err(SkippedSensor {
            name: sensor.name().to_string(),
            reason,
        });
    }
    Ok(sensor)
}

/// Locks a `Mutex`, recovering rather than panicking if a prior holder
/// panicked while holding it — matches the poison-recovery discipline
/// already established by `osiris-sensors-process` and `osiris-generator`'s
/// `lock_health()` (a poisoned lock here still holds a fully-formed
/// `AgentLifecycle`/`Vec<String>`, so recovering is safe).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Agent {
    pub async fn start(
        config: AgentConfig,
        host: HostRef,
        boot_id: String,
    ) -> Result<Arc<Self>, AgentError> {
        let cancellation = CancellationToken::new();
        let (raw_tx, mut raw_rx) = mpsc::channel(1024);

        let overlay_path = policy::overlay_path(&config.spool_path);
        let (policy_rt, heartbeat_rx) = PolicyRuntime::new(config.fleet.health_interval_secs);
        let overlay = policy::load_overlay(&overlay_path).unwrap_or_default();
        policy_rt.set(&overlay);
        let policy_rt = Arc::new(policy_rt);

        let mut candidate_sensors: Vec<Box<dyn Sensor>> = vec![];
        let mut skipped: Vec<SkippedSensor> = vec![];
        for name in STARTUP_ORDER {
            let Some(sensor) = build_sensor(&config, name) else {
                continue;
            };
            if overlay.sensors.get(name) == Some(&false) {
                skipped.push(SkippedSensor {
                    name: name.to_string(),
                    reason: DISABLED_BY_POLICY.into(),
                });
                continue;
            }
            candidate_sensors.push(sensor);
        }
        if config.enable_synthetic {
            let base_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let scenario = match config.synthetic_scenario.as_deref() {
                Some("web_shell_drop") => web_shell_drop_scenario(base_ts),
                Some("network_beacon") => network_beacon_scenario(base_ts),
                Some("network_download_then_write") => {
                    network_download_then_write_scenario(base_ts)
                }
                Some("ssh_sudo_escalation") => ssh_sudo_escalation_scenario(base_ts),
                Some("persistence_via_systemd_service") => {
                    persistence_via_systemd_service_scenario(base_ts)
                }
                Some("container_deploy_in_remote_session") => {
                    container_deploy_in_remote_session_scenario(base_ts)
                }
                Some("exec_chain") | None => exec_chain_scenario(base_ts),
                Some(other) => {
                    tracing::warn!(
                        scenario = other,
                        "unknown synthetic_scenario; falling back to exec_chain"
                    );
                    exec_chain_scenario(base_ts)
                }
            };
            candidate_sensors.push(Box::new(SyntheticSensor::new(scenario)));
        }

        let mut running_sensors: Vec<Box<dyn Sensor>> = vec![];
        for sensor in candidate_sensors {
            match start_sensor(sensor, raw_tx.clone(), cancellation.clone()).await {
                Ok(sensor) => running_sensors.push(sensor),
                Err(skip) => skipped.push(skip),
            }
        }
        let health_raw_tx = raw_tx.clone();

        let metrics = Arc::new(MetricsRegistry::new());
        let (bus, receivers) = EventBus::new(metrics.clone());
        let sink: Arc<dyn Sink> = Arc::new(SpoolFileSink::open(&config.spool_path).await?);
        let drain_handle = tokio::spawn(run_drain_loop(
            receivers,
            sink,
            metrics.clone(),
            cancellation.clone(),
        ));

        let bus = Arc::new(bus);
        let proc_root = config
            .proc_root
            .clone()
            .unwrap_or_else(|| "/proc".to_string());
        let host_id = host.host_id;
        let mut pipeline = Pipeline::new(host, boot_id).with_proc_root(proc_root);
        let k8s_refresher =
            match crate::k8s::start_pod_cache(&config.k8s_context, &cancellation).await {
                Some((cache, handle)) => {
                    pipeline = pipeline.with_pod_lookup(Arc::new(cache));
                    Some(handle)
                }
                None => None,
            };
        let pipeline_cancellation = cancellation.clone();
        let pipeline_bus = bus.clone();
        let pipeline_policy = policy_rt.clone();
        let dropped = metrics.counter("events_dropped_by_policy");
        let pipeline_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_raw = raw_rx.recv() => {
                        match maybe_raw {
                            Some(raw) => {
                                let mut prioritized = pipeline.process(raw);
                                if pipeline_policy.allows(prioritized.event.event_type) {
                                    pipeline_policy.apply_field_rules(&mut prioritized.event);
                                    pipeline_bus.enqueue(prioritized);
                                } else {
                                    dropped.increment();
                                }
                            }
                            None => break,
                        }
                    }
                    _ = pipeline_cancellation.cancelled() => break,
                }
            }
        });

        let mut tasks = vec![pipeline_handle, drain_handle];
        tasks.extend(k8s_refresher);
        if let Some(forward) = &config.forward {
            let forwarder_config = osiris_transport::client::ForwarderConfig::new(
                forward.server_addr.clone(),
                forward.server_name.clone(),
                forward.ca.clone(),
                forward.cert.clone(),
                forward.key.clone(),
                config.spool_path.clone(),
            );
            let forwarder_cancellation = cancellation.clone();
            tasks.push(tokio::spawn(async move {
                // Unusable TLS material must not take the Agent down: it keeps
                // spooling and the operator sees this error.
                if let Err(e) =
                    osiris_transport::client::run_forwarder(forwarder_config, forwarder_cancellation)
                        .await
                {
                    tracing::error!(error = %e, "forwarder not started; events stay in the local spool");
                }
            }));
        }

        let health_cancellation = cancellation.clone();
        let agent = Arc::new(Self {
            lifecycle: Mutex::new(AgentLifecycle::Running),
            sensors: tokio::sync::Mutex::new(running_sensors),
            skipped_sensors: Mutex::new(skipped),
            cancellation,
            background_tasks: tokio::sync::Mutex::new(tasks),
            config: config.clone(),
            raw_tx,
            policy: policy_rt,
            overlay_path,
            apply_lock: tokio::sync::Mutex::new(()),
        });

        // Control starts after the Agent exists so it can drive it.
        if let Some(control) = &config.control {
            let handle = crate::control::start_control(
                control,
                host_id,
                &config.spool_path,
                Arc::downgrade(&agent),
                agent.cancellation.clone(),
            )
            .await;
            agent.background_tasks.lock().await.extend(handle);
        }

        // Phase 9d-1: periodic AGENT_HEALTH heartbeat. Spawned after `agent`
        // exists so it can reuse status_snapshot()'s existing sensor-health
        // readout instead of re-polling sensors directly.
        {
            let mut heartbeat_rx = heartbeat_rx;
            let health_agent = agent.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let secs = (*heartbeat_rx.borrow()).max(1);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                        Ok(()) = heartbeat_rx.changed() => continue,
                        _ = health_cancellation.cancelled() => break,
                    }
                    let status = health_agent.status_snapshot().await;
                    let mut aggregator = osiris_health::HealthAggregator::new();
                    for s in &status.sensors {
                        aggregator.record_sensor(s.to_agent_health());
                    }
                    let raw = osiris_sensor_api::RawEvent::AgentHealth(
                        osiris_sensor_api::AgentHealthRaw {
                            agent_version: env!("CARGO_PKG_VERSION").to_string(),
                            health: aggregator.aggregate(),
                            timestamp_ns: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as u64,
                            policy_hash: health_agent.policy.policy_hash_hex(),
                        },
                    );
                    if health_raw_tx.send(raw).await.is_err() {
                        break; // pipeline task gone; agent is shutting down
                    }
                }
            });
            agent.background_tasks.lock().await.push(handle);
        }

        Ok(agent)
    }

    pub fn policy(&self) -> &Arc<PolicyRuntime> {
        &self.policy
    }

    pub fn overlay_path(&self) -> &std::path::Path {
        &self.overlay_path
    }

    pub async fn set_sensor_enabled(&self, name: &str, enabled: bool) -> SensorChange {
        let mut sensors = self.sensors.lock().await;
        let position = sensors.iter().position(|s| s.name() == name);
        match (enabled, position) {
            (false, Some(i)) => {
                let mut sensor = sensors.remove(i);
                drop(sensors);
                let _ = sensor.stop().await;
                self.mark_disabled(name, true);
                SensorChange::Stopped
            }
            (false, None) => {
                if build_sensor(&self.config, name).is_some() {
                    self.mark_disabled(name, true);
                }
                SensorChange::Unchanged
            }
            (true, Some(_)) => SensorChange::Unchanged,
            (true, None) => {
                drop(sensors);
                // Only a sensor this policy switched off is restarted; one
                // that never ran keeps its startup skip entry untouched.
                let disabled_by_policy = lock(&self.skipped_sensors)
                    .iter()
                    .any(|s| s.name == name && s.reason == DISABLED_BY_POLICY);
                if !disabled_by_policy {
                    return SensorChange::Unchanged;
                }
                self.mark_disabled(name, false);
                let Some(sensor) = build_sensor(&self.config, name) else {
                    return SensorChange::NotConfigured;
                };
                match start_sensor(sensor, self.raw_tx.clone(), self.cancellation.clone()).await {
                    Ok(sensor) => {
                        self.sensors.lock().await.push(sensor);
                        SensorChange::Started
                    }
                    Err(skipped) => {
                        let reason = skipped.reason.clone();
                        let mut list = lock(&self.skipped_sensors);
                        list.retain(|s| s.name != name);
                        list.push(skipped);
                        SensorChange::Failed(reason)
                    }
                }
            }
        }
    }

    /// Keeps exactly one "disabled by policy" entry per disabled sensor.
    fn mark_disabled(&self, name: &str, disabled: bool) {
        let mut skipped = lock(&self.skipped_sensors);
        skipped.retain(|s| !(s.name == name && s.reason == DISABLED_BY_POLICY));
        if disabled {
            skipped.push(SkippedSensor {
                name: name.to_string(),
                reason: DISABLED_BY_POLICY.into(),
            });
        }
    }

    /// Applies an already-validated (and, by the caller, persisted) policy
    /// live. Sensors the policy leaves unset follow agent.yaml (enabled).
    pub async fn apply_policy(&self, policy: &EffectivePolicy) -> String {
        let _serialised = self.apply_lock.lock().await;
        self.policy.set(policy);
        let mut notes = vec![format!(
            "level {}",
            policy
                .telemetry_level
                .map_or("unset".to_string(), |l| format!("{l:?}").to_uppercase())
        )];
        for name in osiris_policy::KNOWN_SENSORS {
            let enabled = policy.sensors.get(name).copied().unwrap_or(true);
            match self.set_sensor_enabled(name, enabled).await {
                SensorChange::Started => notes.push(format!("{name} on")),
                SensorChange::Stopped => notes.push(format!("{name} off")),
                SensorChange::Failed(r) => notes.push(format!("{name} failed: {r}")),
                SensorChange::Unchanged | SensorChange::NotConfigured => {}
            }
        }
        if let Some(h) = policy.heartbeat_interval_secs {
            notes.push(format!("heartbeat {h}s"));
        }
        notes.join("; ")
    }

    pub async fn status_snapshot(&self) -> AgentStatus {
        let lifecycle = *lock(&self.lifecycle);
        let sensors = self.sensors.lock().await;
        let sensor_health: Vec<SensorHealth> = sensors.iter().map(|s| s.health()).collect();
        let skipped_sensors = lock(&self.skipped_sensors).clone();
        AgentStatus {
            lifecycle,
            sensors: sensor_health,
            skipped_sensors,
        }
    }

    pub fn skipped_sensors(&self) -> Vec<SkippedSensor> {
        lock(&self.skipped_sensors).clone()
    }

    pub async fn shutdown(&self) {
        self.cancellation.cancel();
        let mut sensors = self.sensors.lock().await;
        for sensor in sensors.iter_mut() {
            let _ = sensor.stop().await;
        }
        // Release the sensors lock before awaiting background tasks: the
        // periodic health task calls status_snapshot(), which itself locks
        // self.sensors. Holding the guard across the awaits below would
        // deadlock against that task whenever it is mid-snapshot at
        // shutdown time.
        drop(sensors);

        // Await the pipeline and drain-loop tasks so shutdown genuinely
        // waits for the final drain (finding 3) to complete before
        // returning, rather than cancelling and discarding whatever was
        // still queued in the raw channel / bus lanes. Awaited in spawn
        // order: the pipeline task first (it stops consuming raw events
        // and enqueues whatever it already had onto the bus), then the
        // drain-loop task (whose final_drain pass picks up exactly what
        // the pipeline just enqueued) — so nothing in flight at shutdown
        // time is silently dropped.
        let handles: Vec<_> = self.background_tasks.lock().await.drain(..).collect();
        for handle in handles {
            let _ = handle.await;
        }

        *lock(&self.lifecycle) = AgentLifecycle::Stopped;
    }

    pub async fn serve_status(self: Arc<Self>, addr: SocketAddr) -> Result<(), AgentError> {
        crate::status::serve_status(self, addr)
            .await
            .map_err(AgentError::Status)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use uuid::Uuid;

    pub(crate) fn test_host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    pub(crate) fn base_config(dir: &tempfile::TempDir) -> AgentConfig {
        AgentConfig {
            forward: None,
            control: None,
            audit_log_path: None,
            fs_audit_log_path: None,
            network_proc_root: None,
            identity_audit_log_path: None,
            systemd_audit_log_path: None,
            persistence_watch_paths: vec![],
            container_cgroup_roots: vec![],
            dns_capture: None,
            proc_root: None,
            enable_synthetic: false,
            synthetic_scenario: None,
            cloud_metadata: crate::config::CloudMetadataConfig {
                enabled: false,
                ..Default::default()
            },
            k8s_context: crate::config::K8sContextConfig {
                enabled: false,
                ..Default::default()
            },
            fleet: crate::config::FleetConfig::default(),
            spool_path: dir
                .path()
                .join("spool.ndjson")
                .to_string_lossy()
                .to_string(),
            status_addr: "127.0.0.1:0".to_string(),
        }
    }

    #[test]
    fn build_sensor_dns_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        assert!(build_sensor(&base_config(&dir), "dns").is_none());
    }

    #[test]
    fn build_sensor_dns_configured() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.dns_capture = Some(crate::config::DnsCaptureConfig { interface: None });
        let sensor = build_sensor(&config, "dns").expect("dns sensor built");
        assert_eq!(sensor.name(), "dns");
    }

    #[tokio::test]
    async fn agent_health_event_is_emitted_within_two_intervals() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        // 1s is the minimum health interval the agent accepts; keeping it
        // small bounds the sleep below while still exercising a real tick.
        config.fleet.health_interval_secs = 1;
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();

        // health_interval_secs=1: one full interval plus slack for the tokio scheduler.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let spooled = std::fs::read_to_string(&spool_path).unwrap();
        assert!(
            spooled.contains("\"event_type\":\"AGENT_HEALTH\""),
            "expected an AGENT_HEALTH line in the spool, got: {spooled}"
        );
        agent.shutdown().await;
    }

    async fn kubelet_mock_serving(container_id: &str) -> String {
        use axum::routing::get;
        let body = format!(
            r#"{{"items":[{{"metadata":{{"name":"web-0","namespace":"prod"}},"status":{{"containerStatuses":[{{"containerID":"containerd://{container_id}"}}]}}}}]}}"#
        );
        let router = axum::Router::new().route(
            "/pods",
            get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn container_events_in_the_spool_carry_the_pod_ref_when_k8s_context_is_active() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "tok").unwrap();
        let base = kubelet_mock_serving(&"d00d".repeat(16)).await;

        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("container_deploy_in_remote_session".to_string());
        config.k8s_context = crate::config::K8sContextConfig {
            enabled: true,
            kubelet_url: Some(base),
            token_path: Some(token_path.to_string_lossy().to_string()),
            refresh_secs: 3600,
            ..Default::default()
        };
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert!(
            contents.contains("\"pod_name\":\"web-0\""),
            "spool must carry the resolved pod: {contents}"
        );
        assert!(contents.contains("\"namespace\":\"prod\""));
    }

    #[tokio::test]
    async fn without_k8s_context_the_spool_has_no_pod_ref() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("container_deploy_in_remote_session".to_string());
        // base_config leaves k8s_context disabled.
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert!(!contents.contains("\"pod_name\""));
    }

    #[tokio::test]
    async fn starts_with_synthetic_sensor_and_reaches_running() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.lifecycle, AgentLifecycle::Running);
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "synthetic_generator");

        agent.shutdown().await;
        assert_eq!(
            agent.status_snapshot().await.lifecycle,
            AgentLifecycle::Stopped
        );
    }

    #[tokio::test]
    async fn skips_process_exec_sensor_when_audit_log_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.audit_log_path = Some(dir.path().join("missing.log").to_string_lossy().to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);

        let skipped = agent.skipped_sensors();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, "process_exec");
        assert!(
            skipped[0].reason.contains("audit log not found"),
            "expected the skip reason to explain why, got: {}",
            skipped[0].reason
        );

        // The same skip must be surfaced on the status endpoint's response
        // shape, not just the internal accessor (Global Constraint #11:
        // "health-visible reason").
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "process_exec");
        assert_eq!(status.skipped_sensors[0].reason, skipped[0].reason);

        agent.shutdown().await;
    }

    #[tokio::test]
    async fn synthetic_events_reach_the_spool_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 3);
        assert!(contents.contains("\"PROCESS_EXEC\""));
    }

    #[tokio::test]
    async fn starts_the_filesystem_sensor_when_an_fs_audit_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let fs_log = dir.path().join("fs-audit.log");
        std::fs::write(&fs_log, "").unwrap();
        let mut config = base_config(&dir);
        config.fs_audit_log_path = Some(fs_log.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "filesystem");
        agent.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_applies_leave_exactly_one_running_instance_of_a_sensor() {
        let dir = tempfile::tempdir().unwrap();
        let fs_log = dir.path().join("fs-audit.log");
        std::fs::write(&fs_log, "").unwrap();
        let mut config = base_config(&dir);
        config.fs_audit_log_path = Some(fs_log.to_string_lossy().to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let mut off = EffectivePolicy::default();
        off.sensors.insert("filesystem".into(), false);
        agent.apply_policy(&off).await;
        assert!(agent.status_snapshot().await.sensors.is_empty());

        let on = EffectivePolicy::default();
        let mut joins = Vec::new();
        for _ in 0..8 {
            let (a, p) = (agent.clone(), on.clone());
            joins.push(tokio::spawn(async move { a.apply_policy(&p).await }));
        }
        for j in joins {
            j.await.unwrap();
        }
        let running = agent
            .status_snapshot()
            .await
            .sensors
            .into_iter()
            .filter(|s| s.name == "filesystem")
            .count();
        assert_eq!(running, 1);
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn skips_the_filesystem_sensor_with_a_visible_reason_when_its_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.fs_audit_log_path =
            Some(dir.path().join("missing.log").to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "filesystem");
        assert!(status.skipped_sensors[0]
            .reason
            .contains("audit log not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_web_shell_drop_scenario_reaches_the_spool_file_with_file_events() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("web_shell_drop".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 7);
        assert!(contents.contains("\"PROCESS_EXEC\""));
        assert!(contents.contains("\"FILE_CREATE\""));
        assert!(contents.contains("\"FILE_WRITE\""));
        assert!(contents.contains("\"FILE_RENAME\""));
        assert!(contents.contains("/var/www/html/shell.php"));
    }

    #[tokio::test]
    async fn an_unknown_scenario_name_falls_back_to_the_exec_chain_rather_than_starting_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("nonsense".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 3);
    }

    #[tokio::test]
    async fn starts_the_network_sensor_when_a_proc_root_with_net_tcp_exists() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("fakeproc");
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::write(
            proc_root.join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();
        let mut config = base_config(&dir);
        config.network_proc_root = Some(proc_root.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "network");
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn skips_the_network_sensor_with_a_visible_reason_when_net_tcp_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.network_proc_root = Some(
            dir.path()
                .join("no-such-proc")
                .to_string_lossy()
                .to_string(),
        );

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 0);
        assert_eq!(status.skipped_sensors.len(), 1);
        assert_eq!(status.skipped_sensors[0].name, "network");
        assert!(status.skipped_sensors[0]
            .reason
            .contains("net/tcp not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_network_beacon_scenario_reaches_the_spool_file_with_dns_and_network_events() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("network_beacon".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 6);
        assert!(contents.contains("\"DNS_QUERY\""));
        assert!(contents.contains("\"NETWORK_CONNECT\""));
        assert!(contents.contains("\"NETWORK_CLOSE\""));
        assert!(contents.contains("cdn-assets.xyz"));
    }

    #[tokio::test]
    async fn the_network_download_then_write_scenario_reaches_the_spool_file() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("network_download_then_write".to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert_eq!(contents.lines().count(), 5);
        assert!(contents.contains("\"NETWORK_CONNECT\""));
        assert!(contents.contains("\"FILE_CREATE\""));
        assert!(contents.contains("203.0.113.90"));
        assert!(contents.contains("/tmp/payload"));
    }

    #[tokio::test]
    async fn the_identity_sensor_is_skipped_with_a_reason_when_its_log_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = false;
        config.identity_audit_log_path =
            Some(dir.path().join("missing.log").to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let skipped = agent.skipped_sensors();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, "identity");
        assert!(skipped[0].reason.contains("audit log not found"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_identity_sensor_starts_when_its_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let identity_log = dir.path().join("identity-audit.log");
        std::fs::write(&identity_log, "").unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = false;
        config.identity_audit_log_path = Some(identity_log.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert_eq!(status.sensors.len(), 1);
        assert_eq!(status.sensors[0].name, "identity");
        assert!(status.skipped_sensors.is_empty());
        agent.shutdown().await;
    }

    /// The scenario selector must reach the new scenario; an unknown name
    /// still falls back to exec_chain with a warning, unchanged.
    #[tokio::test]
    async fn the_ssh_sudo_escalation_scenario_is_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("ssh_sudo_escalation".to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        agent.shutdown().await;

        let spool = std::fs::read_to_string(dir.path().join("spool.ndjson")).unwrap();
        let lines: Vec<&str> = spool.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            9,
            "all nine scenario events must reach the spool"
        );
        let categories: std::collections::HashSet<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["category"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
            assert!(categories.contains(expected), "missing category {expected}");
        }
    }

    #[tokio::test]
    async fn the_persistence_via_systemd_service_scenario_is_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("persistence_via_systemd_service".to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let snapshot = agent.status_snapshot().await;
        assert!(snapshot
            .sensors
            .iter()
            .any(|s| s.name == "synthetic_generator"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn the_container_deploy_in_remote_session_scenario_is_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("container_deploy_in_remote_session".to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let snapshot = agent.status_snapshot().await;
        assert!(snapshot
            .sensors
            .iter()
            .any(|s| s.name == "synthetic_generator"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn a_configured_but_missing_systemd_audit_log_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.systemd_audit_log_path = Some(
            dir.path()
                .join("missing-audit.log")
                .to_string_lossy()
                .to_string(),
        );
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let snapshot = agent.status_snapshot().await;
        assert!(snapshot.skipped_sensors.iter().any(|s| s.name == "systemd"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn starts_the_systemd_sensor_when_the_audit_log_exists() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = dir.path().join("systemd-audit.log");
        std::fs::write(&audit_log, "").unwrap();
        let mut config = base_config(&dir);
        config.systemd_audit_log_path = Some(audit_log.to_string_lossy().to_string());

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert!(status.sensors.iter().any(|s| s.name == "systemd"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn starts_the_persistence_sensor_when_a_watch_target_exists() {
        let dir = tempfile::tempdir().unwrap();
        let watch_dir = dir.path().join("systemd-units");
        std::fs::create_dir(&watch_dir).unwrap();
        let mut config = base_config(&dir);
        config.persistence_watch_paths = vec![osiris_sensors_persistence::PersistenceWatchTarget {
            path: watch_dir.to_string_lossy().to_string(),
            kind: osiris_sensors_persistence::PersistenceWatchKind::SystemdUnitDir,
        }];

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert!(status.sensors.iter().any(|s| s.name == "persistence"));
        agent.shutdown().await;
    }

    /// Phase 5 plan Task 7: proof `ContainerSensor` is actually constructed
    /// in `Agent::start`, not just defined — the exact bug Phase 4b's own
    /// final review caught for its two sensors, guarded against here from
    /// the start.
    #[tokio::test]
    async fn starts_the_container_sensor_when_a_cgroup_root_exists() {
        let dir = tempfile::tempdir().unwrap();
        let cgroup_dir = dir.path().join("system.slice");
        std::fs::create_dir(&cgroup_dir).unwrap();
        let mut config = base_config(&dir);
        config.container_cgroup_roots = vec![osiris_sensors_container::ContainerCgroupRoot {
            path: cgroup_dir.to_string_lossy().to_string(),
        }];

        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let status = agent.status_snapshot().await;
        assert!(status.sensors.iter().any(|s| s.name == "container"));
        agent.shutdown().await;
    }

    #[tokio::test]
    async fn minimal_level_drops_file_writes_but_keeps_agent_health() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("web_shell_drop".to_string());
        config.fleet.health_interval_secs = 1;
        let overlay = crate::policy::overlay_path(&config.spool_path);
        crate::policy::save_overlay(
            &overlay,
            &EffectivePolicy {
                telemetry_level: Some(osiris_policy::TelemetryLevel::Minimal),
                ..Default::default()
            },
        )
        .unwrap();
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        agent.shutdown().await;
        let spooled = std::fs::read_to_string(&spool).unwrap();
        assert!(spooled.contains("\"event_type\":\"AGENT_HEALTH\""));
        assert!(
            !spooled.contains("\"event_type\":\"FILE_WRITE\""),
            "{spooled}"
        );
        assert!(
            spooled.contains("\"policy_hash\":\""),
            "the heartbeat reports the applied hash"
        );
    }

    #[tokio::test]
    async fn without_an_overlay_the_heartbeat_reports_a_null_policy_hash() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.fleet.health_interval_secs = 1;
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        agent.shutdown().await;
        assert!(std::fs::read_to_string(&spool)
            .unwrap()
            .contains("\"policy_hash\":null"));
    }

    #[tokio::test]
    async fn a_policy_stops_and_restarts_a_real_sensor() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::write(
            proc_root.join("net/tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();
        config.network_proc_root = Some(proc_root.to_string_lossy().to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let names = |s: &crate::status::AgentStatus| {
            s.sensors.iter().map(|h| h.name.clone()).collect::<Vec<_>>()
        };
        assert!(names(&agent.status_snapshot().await).contains(&"network".to_string()));

        let mut off = EffectivePolicy::default();
        off.sensors.insert("network".into(), false);
        let summary = agent.apply_policy(&off).await;
        assert!(summary.contains("network off"), "{summary}");
        let status = agent.status_snapshot().await;
        assert!(!names(&status).contains(&"network".to_string()));
        assert!(status
            .skipped_sensors
            .iter()
            .any(|s| s.name == "network" && s.reason == "disabled by policy"));

        let summary = agent.apply_policy(&EffectivePolicy::default()).await;
        assert!(summary.contains("network on"), "{summary}");
        let status = agent.status_snapshot().await;
        assert!(names(&status).contains(&"network".to_string()));
        assert!(!status
            .skipped_sensors
            .iter()
            .any(|s| s.reason == "disabled by policy"));
        agent.shutdown().await;
    }

    /// Regression (Phase 11a final review I-1): switching one sensor off at
    /// runtime must cancel only that sensor, not the agent-wide token that
    /// the pipeline, drain loop, heartbeat, forwarder and control channel
    /// select on; and a re-enabled sensor must get a live token again.
    #[tokio::test]
    async fn a_runtime_sensor_stop_leaves_the_agent_running_and_a_restart_works() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        std::fs::write(proc_root.join("net/tcp"), header).unwrap();
        config.network_proc_root = Some(proc_root.to_string_lossy().to_string());
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();

        let mut off = EffectivePolicy::default();
        off.sensors.insert("network".into(), false);
        let summary = agent.apply_policy(&off).await;
        assert!(summary.contains("network off"), "{summary}");
        assert!(
            !agent.cancellation.is_cancelled(),
            "stopping one sensor must not cancel the whole agent"
        );

        let summary = agent.apply_policy(&EffectivePolicy::default()).await;
        assert!(summary.contains("network on"), "{summary}");

        // The restarted sensor must poll again, and its event must make it
        // through the (still running) pipeline into the spool.
        std::fs::write(
            proc_root.join("net/tcp"),
            format!("{header}  0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n"),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let emitted = |s: &crate::status::AgentStatus| {
            s.sensors
                .iter()
                .find(|h| h.name == "network")
                .map(|h| h.events_emitted_total)
                .unwrap_or(0)
        };
        while emitted(&agent.status_snapshot().await) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            emitted(&agent.status_snapshot().await) >= 1,
            "the re-enabled sensor must emit again"
        );
        agent.shutdown().await;
        let spooled = std::fs::read_to_string(&spool).unwrap();
        assert!(
            spooled.contains("203.27.103.50"),
            "the pipeline must still ship events after a sensor stop: {spooled}"
        );
    }

    #[tokio::test]
    async fn reapplying_a_policy_does_not_retry_or_duplicate_a_never_runnable_sensor() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = base_config(&dir);
        config.network_proc_root = Some(
            dir.path()
                .join("no-such-proc")
                .to_string_lossy()
                .to_string(),
        );
        let agent = Agent::start(config, test_host(), "boot-1".to_string())
            .await
            .unwrap();
        let before = agent.skipped_sensors();
        assert_eq!(before.len(), 1);

        let policy = EffectivePolicy {
            telemetry_level: Some(osiris_policy::TelemetryLevel::Standard),
            ..Default::default()
        };
        for _ in 0..2 {
            let summary = agent.apply_policy(&policy).await;
            assert!(!summary.contains("failed"), "{summary}");
            let after = agent.skipped_sensors();
            assert_eq!(after.len(), 1);
            assert_eq!(after[0].reason, before[0].reason);
        }

        // Disabled by policy, then re-enabled while still not runnable:
        // one entry, carrying the real failure reason.
        let mut off = EffectivePolicy::default();
        off.sensors.insert("network".into(), false);
        agent.apply_policy(&off).await;
        let summary = agent.apply_policy(&EffectivePolicy::default()).await;
        assert!(summary.contains("network failed"), "{summary}");
        let skipped = agent.skipped_sensors();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_ne!(skipped[0].reason, "disabled by policy");
        agent.shutdown().await;
    }
}
