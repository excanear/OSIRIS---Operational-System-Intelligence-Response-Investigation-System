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

/// Minimal agent.yaml shape for Phase 1 (ARCHITECTURE.md §3.1 point 2's
/// full ConfigManager — schema validation, inotify hot-reload — is
/// deferred per plan Global Constraints #6; this loads once at startup).
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
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
        assert_eq!(config.persistence_watch_paths[0].path, "/etc/systemd/system");
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
}
