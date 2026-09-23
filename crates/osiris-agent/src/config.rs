use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
}

/// Optional Cloud metadata probe config (ARCHITECTURE.md §21.4). On by
/// default; the per-provider base URLs exist for tests and proxied
/// metadata services — they are not auto-discovery.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudMetadataConfig {
    #[serde(default = "default_cloud_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub aws_base_url: Option<String>,
    #[serde(default)]
    pub azure_base_url: Option<String>,
    #[serde(default)]
    pub gcp_base_url: Option<String>,
}

fn default_cloud_enabled() -> bool {
    true
}

impl Default for CloudMetadataConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            aws_base_url: None,
            azure_base_url: None,
            gcp_base_url: None,
        }
    }
}

/// Phase 9d-1: how often the Agent emits an AGENT_HEALTH event. Always
/// on (unlike `control`/`forward`, which are opt-in features) — the
/// Fleet Manager registry depends on every agent heartbeating.
#[derive(Debug, Clone, Deserialize)]
pub struct FleetConfig {
    #[serde(default = "default_health_interval_secs")]
    pub health_interval_secs: u64,
}

fn default_health_interval_secs() -> u64 {
    60
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            health_interval_secs: default_health_interval_secs(),
        }
    }
}

/// Optional Kubernetes context (Phase 8e, ARCHITECTURE.md §21.3): resolves
/// container -> pod from the node's kubelet. On by default but active only
/// when a kubelet URL is configured or a service-account token exists, so a
/// non-Kubernetes host makes no connection. TLS verification is on; use
/// `ca_path` for the kubelet's CA, or `insecure_skip_verify` (a documented
/// risk) as an explicit opt-in. With `insecure_skip_verify` the service-account
/// token is sent only to a loopback kubelet (a warning is logged at startup);
/// for any other host it is withheld, as for plain http. `refresh_secs` is
/// raised to a floor of 5.
#[derive(Debug, Clone, Deserialize)]
pub struct K8sContextConfig {
    #[serde(default = "default_k8s_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub kubelet_url: Option<String>,
    #[serde(default)]
    pub token_path: Option<String>,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default = "default_k8s_refresh_secs")]
    pub refresh_secs: u64,
}

fn default_k8s_enabled() -> bool {
    true
}

fn default_k8s_refresh_secs() -> u64 {
    30
}

impl Default for K8sContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kubelet_url: None,
            token_path: None,
            ca_path: None,
            insecure_skip_verify: false,
            refresh_secs: 30,
        }
    }
}

/// Phase 9a: ship the spool to a remote Server over mutual TLS. Absent = the
/// Agent only writes `spool_path` (a same-host Server tails it). Certificates
/// come from `osiris pki issue-agent` (bound to this host's id).
#[derive(Debug, Clone, Deserialize)]
pub struct ForwardConfig {
    /// `host:port` of the Server's agent listener.
    pub server_addr: String,
    /// The name the Server's certificate must be valid for.
    pub server_name: String,
    /// CA that signed the Server's certificate (PEM).
    pub ca: String,
    /// This Agent's certificate and private key (PEM).
    pub cert: String,
    pub key: String,
}

/// Phase 9c-1: a control connection over which the Server can send signed
/// commands (terminate a process, quarantine a file). Absent = no control
/// connection. The Agent verifies every command against `command_public_key`
/// and fails closed if that key cannot be loaded.
#[derive(Debug, Clone, Deserialize)]
pub struct ControlConfig {
    /// `host:port` of the Server's control listener.
    pub server_addr: String,
    /// The name the Server's certificate must be valid for.
    pub server_name: String,
    /// CA that signed the Server's certificate (PEM).
    pub ca: String,
    /// This Agent's certificate and private key (PEM).
    pub cert: String,
    pub key: String,
    /// Path to the Server's command-signing public key.
    pub command_public_key: String,
    /// Quarantine vault directory (created 0700 on Linux).
    pub vault_dir: String,
}

/// Minimal agent.yaml shape for Phase 1 (ARCHITECTURE.md §3.1 point 2's
/// full ConfigManager — schema validation, inotify hot-reload — is
/// deferred per plan Global Constraints #6; this loads once at startup).
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Remote delivery over mTLS (Phase 9a); `None` keeps spool-only behaviour.
    #[serde(default)]
    pub forward: Option<ForwardConfig>,
    /// Signed-command control connection (Phase 9c-1); `None` = disabled.
    #[serde(default)]
    pub control: Option<ControlConfig>,
    /// Cloud metadata probe (Phase 8d). Defaults to enabled, no overrides,
    /// so every pre-8d agent.yaml still loads.
    #[serde(default)]
    pub cloud_metadata: CloudMetadataConfig,
    /// Kubernetes context (Phase 8e). Defaults to enabled-but-gated, so
    /// every pre-8e agent.yaml still loads.
    #[serde(default)]
    pub k8s_context: K8sContextConfig,
    /// AGENT_HEALTH heartbeat cadence (Phase 9d-1). Defaults to enabled at
    /// 60s, so every pre-9d-1 agent.yaml still loads.
    #[serde(default)]
    pub fleet: FleetConfig,
    /// Path to a Linux auditd-style log file for the Process/Exec sensor's
    /// audit backend. If absent or the file doesn't exist, that sensor is
    /// skipped (capabilities()-driven, never silently).
    #[serde(default)]
    pub audit_log_path: Option<String>,
    /// Path to a Linux auditd-style log file for the Filesystem sensor's
    /// audit backend (a separate file from `audit_log_path` so an operator
    /// can point the two sensors at different, rule-scoped logs; pointing
    /// both at the same file is also valid — each sensor ignores the
    /// records the other consumes). Skipped, never silently, if absent.
    #[serde(default)]
    pub fs_audit_log_path: Option<String>,
    /// Directory to poll for `/proc/net/tcp`-style Network sensor input
    /// (a real deployment points this at `/proc`). If absent or its
    /// `net/tcp` file doesn't exist, that sensor is skipped
    /// (capabilities()-driven, never silently).
    #[serde(default)]
    pub network_proc_root: Option<String>,
    /// Path to a Linux auditd-style log file for the Identity sensor's
    /// audit backend, carrying `USER_*`, `USER_CMD` and `setuid`/`setgid`
    /// `SYSCALL` records (Phase 4a plan Global Constraints #2/#4). A
    /// separate key from `audit_log_path`/`fs_audit_log_path` so an
    /// operator can point each sensor at its own rule-scoped log; pointing
    /// several of them at the same file is equally valid, because each
    /// sensor ignores the records the others consume. Skipped, never
    /// silently, if absent or non-existent.
    #[serde(default)]
    pub identity_audit_log_path: Option<String>,
    /// Path to a Linux auditd-style log file for the Systemd sensor's audit
    /// backend, carrying `SERVICE_START`/`SERVICE_STOP` records (plan
    /// Global Constraint #1). Skipped, never silently, if absent or
    /// non-existent.
    #[serde(default)]
    pub systemd_audit_log_path: Option<String>,
    /// Persistence Monitor's config-declared watch targets (plan Global
    /// Constraint #4). Empty by default, in which case the sensor is
    /// skipped (capabilities()-driven, never silently) — same pattern
    /// every other optional sensor config uses, adapted to a list rather
    /// than a single path since this sensor watches several locations at
    /// once.
    #[serde(default)]
    pub persistence_watch_paths: Vec<osiris_sensors_persistence::PersistenceWatchTarget>,
    /// Container sensor's config-declared cgroup roots to scan (Phase 5
    /// plan Task 7). Empty by default, in which case the sensor is
    /// skipped (capabilities()-driven, never silently) — same pattern
    /// `persistence_watch_paths` established.
    #[serde(default)]
    pub container_cgroup_roots: Vec<osiris_sensors_container::ContainerCgroupRoot>,
    /// Procfs root the pipeline's `NsCgroupResolver` reads per-process
    /// namespace/cgroup context from (Phase 5 plan Task 7). Defaults to
    /// `/proc` when absent — new surface this phase introduces (no earlier
    /// sensor reads `/proc` directly by pid), not a changed default for any
    /// existing sensor.
    #[serde(default)]
    pub proc_root: Option<String>,
    /// Enables the synthetic/generator sensor (always available).
    #[serde(default)]
    pub enable_synthetic: bool,
    /// Which canned scenario the synthetic sensor emits: `"exec_chain"`
    /// (default, Phase 1's sshd->bash->curl), `"web_shell_drop"` (that
    /// chain continued into the filesystem), `"network_beacon"` (that
    /// chain continued into DNS and network), `"ssh_sudo_escalation"`
    /// (§26's trace from its first step: login, shell, sudo escalation,
    /// file write, outbound connection), `"persistence_via_systemd_service"`
    /// (that same opening continued into a backdoor systemd unit install and
    /// start), `"container_deploy_in_remote_session"` (that same opening
    /// continued into a container create+start instead), or
    /// `"network_download_then_write"` (curl connects, then the same
    /// process writes a file — §26's own worked trace verbatim, and the
    /// Phase 6 shipped sequence rule's positive fixture). Ignored unless
    /// `enable_synthetic` is true.
    #[serde(default)]
    pub synthetic_scenario: Option<String>,
    /// Path to the NDJSON spool file (plan Global Constraints #3).
    pub spool_path: String,
    /// Loopback address for the local status HTTP endpoint (plan Global
    /// Constraints #4).
    pub status_addr: String,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: AgentConfig = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_a_minimal_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: true\nspool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.enable_synthetic);
        assert!(config.audit_log_path.is_none());
        assert_eq!(config.status_addr, "127.0.0.1:9200");
    }

    #[test]
    fn the_new_phase_2_fields_default_to_none_so_phase_1_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: true\nspool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.fs_audit_log_path.is_none());
        assert!(config.synthetic_scenario.is_none());
        assert!(config.network_proc_root.is_none());
    }

    #[test]
    fn the_new_phase_4a_field_defaults_to_none_so_earlier_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: true\nspool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.identity_audit_log_path.is_none());
    }

    #[test]
    fn loads_an_identity_audit_log_path_when_one_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nidentity_audit_log_path: /var/log/audit/audit.log\n\
             spool_path: /tmp/spool.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(
            config.identity_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
    }

    #[test]
    fn defaults_systemd_and_persistence_config_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.systemd_audit_log_path.is_none());
        assert!(config.persistence_watch_paths.is_empty());
    }

    #[test]
    fn loads_persistence_watch_paths_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n\
             systemd_audit_log_path: /var/log/audit/audit.log\n\
             persistence_watch_paths:\n  \
               - path: /etc/systemd/system\n    kind: systemd_unit_dir\n  \
               - path: /etc/cron.d\n    kind: cron\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(
            config.systemd_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(config.persistence_watch_paths.len(), 2);
        assert_eq!(
            config.persistence_watch_paths[0].path,
            "/etc/systemd/system"
        );
    }

    #[test]
    fn defaults_container_cgroup_roots_and_proc_root_to_empty_and_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.container_cgroup_roots.is_empty());
        assert!(config.proc_root.is_none());
    }

    #[test]
    fn loads_container_cgroup_roots_and_proc_root_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "enable_synthetic: false\nspool_path: /tmp/spool.ndjson\n\
             status_addr: 127.0.0.1:9200\n\
             proc_root: /proc\n\
             container_cgroup_roots:\n  \
               - path: /sys/fs/cgroup/system.slice\n  \
               - path: /sys/fs/cgroup/kubepods.slice\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(config.proc_root.as_deref(), Some("/proc"));
        assert_eq!(config.container_cgroup_roots.len(), 2);
        assert_eq!(
            config.container_cgroup_roots[0].path,
            "/sys/fs/cgroup/system.slice"
        );
    }

    #[test]
    fn missing_file_returns_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = AgentConfig::load(&dir.path().join("missing.yaml"));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn cloud_metadata_defaults_to_enabled_with_no_overrides_so_old_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.cloud_metadata.enabled);
        assert!(config.cloud_metadata.aws_base_url.is_none());
    }

    #[test]
    fn forward_is_optional_and_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson
status_addr: 127.0.0.1:9200
",
        )
        .unwrap();
        assert!(AgentConfig::load(&path).unwrap().forward.is_none());
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson
status_addr: 127.0.0.1:9200
forward:
  server_addr: srv:9443
  server_name: srv
  ca: /ca.pem
  cert: /a.pem
  key: /a.key
",
        )
        .unwrap();
        let forward = AgentConfig::load(&path).unwrap().forward.unwrap();
        assert_eq!(forward.server_addr, "srv:9443");
        assert_eq!(forward.server_name, "srv");
    }

    #[test]
    fn control_is_optional_and_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /s
status_addr: 127.0.0.1:9200
",
        )
        .unwrap();
        assert!(AgentConfig::load(&path).unwrap().control.is_none());
        std::fs::write(
            &path,
            "spool_path: /s
status_addr: 127.0.0.1:9200
control:
  server_addr: srv:9444
  server_name: srv
  ca: /ca.pem
  cert: /a.pem
  key: /a.key
  command_public_key: /cmd.pub
  vault_dir: /var/lib/osiris/vault
",
        )
        .unwrap();
        let c = AgentConfig::load(&path).unwrap().control.unwrap();
        assert_eq!(c.server_addr, "srv:9444");
        assert_eq!(c.vault_dir, "/var/lib/osiris/vault");
    }

    #[test]
    fn k8s_context_defaults_so_pre_8e_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.k8s_context.enabled);
        assert!(config.k8s_context.kubelet_url.is_none());
        assert!(config.k8s_context.token_path.is_none());
        assert!(config.k8s_context.ca_path.is_none());
        assert!(!config.k8s_context.insecure_skip_verify);
        assert_eq!(config.k8s_context.refresh_secs, 30);
    }

    #[test]
    fn k8s_context_section_parses_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\nk8s_context:\n  enabled: false\n  kubelet_url: https://10.0.0.1:10250\n  ca_path: /ca.pem\n  refresh_secs: 5\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(!config.k8s_context.enabled);
        assert_eq!(
            config.k8s_context.kubelet_url.as_deref(),
            Some("https://10.0.0.1:10250")
        );
        assert_eq!(config.k8s_context.ca_path.as_deref(), Some("/ca.pem"));
        assert_eq!(config.k8s_context.refresh_secs, 5);
    }

    #[test]
    fn cloud_metadata_section_parses_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\ncloud_metadata:\n  enabled: false\n  gcp_base_url: http://127.0.0.1:9\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(!config.cloud_metadata.enabled);
        assert_eq!(
            config.cloud_metadata.gcp_base_url.as_deref(),
            Some("http://127.0.0.1:9")
        );
    }
}
