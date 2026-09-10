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

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub db_path: String,
    pub spool_path: String,
    pub listen_addr: String,
    pub rules_dir: String,
    /// Phase 6: the Baseline Engine's own SQLite file (`osiris-baseline`
    /// owns its schema independently of `db_path`'s event/alert/
    /// relationship/risk tables — Phase 6 plan Global Constraint #3).
    /// Optional so an existing config file with no `baseline_db_path` keeps
    /// loading unmodified; `main.rs` applies a documented default.
    #[serde(default)]
    pub baseline_db_path: Option<String>,
    /// Phase 6: the Risk Engine's weight config (`config/risk/weights.yaml`
    /// by default — see `main.rs`).
    #[serde(default)]
    pub risk_weights_path: Option<String>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(serde_yaml::from_str(&contents)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_a_minimal_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert!(config.baseline_db_path.is_none());
        assert!(config.risk_weights_path.is_none());
    }

    #[test]
    fn loads_the_phase_6_fields_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\nbaseline_db_path: /tmp/baseline.db\nrisk_weights_path: /etc/osiris/risk/weights.yaml\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.baseline_db_path.as_deref(), Some("/tmp/baseline.db"));
        assert_eq!(
            config.risk_weights_path.as_deref(),
            Some("/etc/osiris/risk/weights.yaml")
        );
    }
}
