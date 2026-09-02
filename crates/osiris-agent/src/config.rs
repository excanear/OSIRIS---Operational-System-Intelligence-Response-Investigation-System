use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}: {source}")]
    Read { path: PathBuf, #[source] source: std::io::Error },
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
    /// Enables the synthetic/generator sensor (always available).
    #[serde(default)]
    pub enable_synthetic: bool,
    /// Path to the NDJSON spool file (plan Global Constraints #3).
    pub spool_path: String,
    /// Loopback address for the local status HTTP endpoint (plan Global
    /// Constraints #4).
    pub status_addr: String,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
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
    fn missing_file_returns_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = AgentConfig::load(&dir.path().join("missing.yaml"));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }
}
