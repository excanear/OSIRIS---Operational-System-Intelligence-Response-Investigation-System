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
    #[error("invalid config: {0}")]
    Invalid(String),
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
    /// Phase 7a: the Incident/Evidence/link control-plane stores' own
    /// SQLite files (ARCHITECTURE.md §10.3), independent of `db_path`'s
    /// telemetry tables — same posture `baseline_db_path` already
    /// established. All four are optional so an existing config keeps
    /// loading unmodified; `main.rs` applies documented defaults.
    #[serde(default)]
    pub incidents_db_path: Option<String>,
    #[serde(default)]
    pub evidence_db_path: Option<String>,
    #[serde(default)]
    pub links_db_path: Option<String>,
    #[serde(default)]
    pub investigate_audit_log_path: Option<String>,
    /// Phase 7b-1: dev-only permissive CORS for the Console's Vite dev
    /// server (a different origin/port than osiris-server). `None`/`false`
    /// (the default for any config that doesn't mention it) leaves CORS
    /// disabled — this must never be enabled unconditionally in a way a
    /// production deployment could inherit by omission.
    #[serde(default)]
    pub dev_cors: Option<bool>,
    /// Phase 8a: the RBAC/Auth store's own SQLite file (ARCHITECTURE.md
    /// §10.3), independent of `db_path`'s telemetry tables — same posture
    /// `incidents_db_path` etc. already established.
    #[serde(default)]
    pub users_db_path: Option<String>,
    /// Phase 8f: the tenant registry's own SQLite file.
    #[serde(default)]
    pub tenants_db_path: Option<String>,
    /// Phase 8a: session token lifetime in seconds; `main.rs` defaults to
    /// 28800 (8 hours) when absent.
    #[serde(default)]
    pub session_ttl_seconds: Option<u64>,
    /// Phase 9a: mutual-TLS listener for remote Agents. Absent = the Server only
    /// tails `spool_path` (same-host Agent), exactly as before.
    #[serde(default)]
    pub agent_listener: Option<AgentListenerConfig>,
    /// Phase 9b: native TLS for the API/Console listener. Absent = plain HTTP.
    #[serde(default)]
    pub api_tls: Option<ApiTlsConfig>,
    /// Phase 9c-1: server-to-agent command channel. Absent = commands disabled.
    #[serde(default)]
    pub control: Option<ControlServerConfig>,
}

/// Command channel listener (mTLS) and the key commands are signed with.
#[derive(Debug, Clone, Deserialize)]
pub struct ControlServerConfig {
    pub listen_addr: String,
    pub cert: String,
    pub key: String,
    pub client_ca: String,
    /// Hex Ed25519 signing key (see `osiris pki init-command-key`).
    pub command_signing_key: String,
    #[serde(default)]
    pub revoked_hosts: Vec<uuid::Uuid>,
    /// RESERVED - accepted and validated but NOT yet enforced; the control listener currently applies fixed caps of 1024 connections / 16 per IP.
    // Task 7's operator documentation must repeat this reservation.
    #[serde(default = "default_max_connections")]
    pub max_connections: u64,
    /// RESERVED - accepted and validated but NOT yet enforced; the control listener currently applies fixed caps of 1024 connections / 16 per IP.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u64,
    /// How long to wait for an Agent's result (1..=110 s).
    #[serde(default = "default_command_timeout_secs")]
    pub command_timeout_secs: u64,
}

fn default_max_connections() -> u64 {
    1024
}
fn default_max_connections_per_ip() -> u64 {
    16
}
fn default_command_timeout_secs() -> u64 {
    30
}

impl ControlServerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (name, v) in [
            ("cert", &self.cert),
            ("key", &self.key),
            ("client_ca", &self.client_ca),
            ("command_signing_key", &self.command_signing_key),
        ] {
            if v.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "control.{name} must not be empty"
                )));
            }
        }
        if self.listen_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(format!(
                "control.listen_addr '{}' is not a valid socket address",
                self.listen_addr
            )));
        }
        for (name, n) in [
            ("max_connections", self.max_connections),
            ("max_connections_per_ip", self.max_connections_per_ip),
        ] {
            if n == 0 || n > tokio::sync::Semaphore::MAX_PERMITS as u64 {
                return Err(ConfigError::Invalid(format!(
                    "control.{name} (reserved, not yet enforced) must be between 1 and {}",
                    tokio::sync::Semaphore::MAX_PERMITS
                )));
            }
        }
        if !(1..=110).contains(&self.command_timeout_secs) {
            return Err(ConfigError::Invalid(
                "control.command_timeout_secs must be between 1 and 110".into(),
            ));
        }
        Ok(())
    }
}

/// PEM certificate chain and private key the API/Console presents (no client auth).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiTlsConfig {
    pub cert: String,
    pub key: String,
    /// Concurrent connection cap (default 1024).
    #[serde(default)]
    pub max_connections: Option<u64>,
    /// Concurrent connections per peer IP (default 16).
    #[serde(default)]
    pub max_connections_per_ip: Option<u64>,
}

impl ApiTlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for (name, v) in [
            ("max_connections", self.max_connections),
            ("max_connections_per_ip", self.max_connections_per_ip),
        ] {
            if let Some(n) = v {
                if n == 0 || n > tokio::sync::Semaphore::MAX_PERMITS as u64 {
                    return Err(ConfigError::Invalid(format!(
                        "api_tls.{name} must be between 1 and {}",
                        tokio::sync::Semaphore::MAX_PERMITS
                    )));
                }
            }
        }
        Ok(())
    }

    /// Listener limits: configured caps over the defaults.
    pub fn limits(&self) -> crate::api_tls::Limits {
        let d = crate::api_tls::Limits::default();
        crate::api_tls::Limits {
            max_connections: self
                .max_connections
                .map_or(d.max_connections, |n| n as usize),
            max_per_ip: self
                .max_connections_per_ip
                .map_or(d.max_per_ip, |n| n as usize),
            ..d
        }
    }
}

/// Where remote Agents connect and how they are authenticated.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentListenerConfig {
    pub listen_addr: String,
    /// The Server's certificate chain and private key (PEM).
    pub cert: String,
    pub key: String,
    /// CA that must have signed every Agent certificate (PEM).
    pub client_ca: String,
    /// Host ids whose certificates are no longer accepted.
    #[serde(default)]
    pub revoked_hosts: Vec<uuid::Uuid>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = serde_yaml::from_str(&contents)?;
        if let Some(t) = &config.api_tls {
            t.validate()?;
        }
        if let Some(c) = &config.control {
            c.validate()?;
        }
        Ok(config)
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

    #[test]
    fn loads_a_config_with_incident_evidence_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\nincidents_db_path: /tmp/incidents.db\nevidence_db_path: /tmp/evidence.db\nlinks_db_path: /tmp/links.db\ninvestigate_audit_log_path: /tmp/investigate-audit.jsonl\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(
            config.incidents_db_path.as_deref(),
            Some("/tmp/incidents.db")
        );
        assert_eq!(config.evidence_db_path.as_deref(), Some("/tmp/evidence.db"));
        assert_eq!(config.links_db_path.as_deref(), Some("/tmp/links.db"));
        assert_eq!(
            config.investigate_audit_log_path.as_deref(),
            Some("/tmp/investigate-audit.jsonl")
        );
    }

    #[test]
    fn loads_a_minimal_config_without_the_new_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert!(config.incidents_db_path.is_none());
    }

    #[test]
    fn agent_listener_is_optional_and_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let base = "db_path: /tmp/e.db
spool_path: /tmp/s
listen_addr: 127.0.0.1:8080
rules_dir: /r
";
        std::fs::write(&path, base).unwrap();
        assert!(ServerConfig::load(&path).unwrap().agent_listener.is_none());
        let host = uuid::Uuid::new_v4();
        std::fs::write(
            &path,
            format!(
                "{base}agent_listener:
  listen_addr: 0.0.0.0:9443
  cert: /s.pem
  key: /s.key
  client_ca: /ca.pem
  revoked_hosts: [\"{host}\"]
"
            ),
        )
        .unwrap();
        let l = ServerConfig::load(&path).unwrap().agent_listener.unwrap();
        assert_eq!(l.listen_addr, "0.0.0.0:9443");
        assert_eq!(l.revoked_hosts, vec![host]);
    }

    #[test]
    fn dev_cors_defaults_to_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.dev_cors, None);
    }

    #[test]
    fn dev_cors_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\ndev_cors: true\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.dev_cors, Some(true));
    }

    #[test]
    fn users_db_path_and_session_ttl_default_to_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert!(config.users_db_path.is_none());
        assert!(config.tenants_db_path.is_none());
        assert!(config.session_ttl_seconds.is_none());
    }

    #[test]
    fn users_db_path_and_session_ttl_parse_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\nusers_db_path: /tmp/users.db\ntenants_db_path: /tmp/tenants.db\nsession_ttl_seconds: 3600\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.users_db_path.as_deref(), Some("/tmp/users.db"));
        assert_eq!(config.tenants_db_path.as_deref(), Some("/tmp/tenants.db"));
        assert_eq!(config.session_ttl_seconds, Some(3600));
    }

    #[test]
    fn api_tls_is_optional_and_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let base = "db_path: /tmp/e.db
spool_path: /tmp/s
listen_addr: 127.0.0.1:8080
rules_dir: /r
";
        std::fs::write(&path, base).unwrap();
        assert!(ServerConfig::load(&path).unwrap().api_tls.is_none());
        std::fs::write(
            &path,
            format!(
                "{base}api_tls:
  cert: /a.pem
  key: /a.key
"
            ),
        )
        .unwrap();
        let t = ServerConfig::load(&path).unwrap().api_tls.unwrap();
        assert_eq!((t.cert.as_str(), t.key.as_str()), ("/a.pem", "/a.key"));
    }

    #[test]
    fn api_tls_limits_are_validated_and_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let base = "db_path: /e
spool_path: /s
listen_addr: 127.0.0.1:8080
rules_dir: /r
api_tls:
  cert: /a
  key: /k
";
        let load = |extra: &str| {
            std::fs::write(&path, format!("{base}{extra}")).unwrap();
            ServerConfig::load(&path)
        };
        let l = load("").unwrap().api_tls.unwrap().limits();
        assert_eq!((l.max_connections, l.max_per_ip), (1024, 16));
        let l = load(
            "  max_connections: 50
  max_connections_per_ip: 3
",
        )
        .unwrap()
        .api_tls
        .unwrap()
        .limits();
        assert_eq!((l.max_connections, l.max_per_ip), (50, 3));
        assert!(load(
            "  max_connections: 0
"
        )
        .is_err());
        assert!(load(
            "  max_connections_per_ip: 0
"
        )
        .is_err());
        assert!(load(
            "  max_connections: 18446744073709551615
"
        )
        .is_err());
    }

    #[test]
    fn control_is_optional_defaults_and_validates_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let base = "db_path: /e\nspool_path: /s\nlisten_addr: 127.0.0.1:8080\nrules_dir: /r\n";
        let load = |extra: &str| {
            std::fs::write(&path, format!("{base}{extra}")).unwrap();
            ServerConfig::load(&path)
        };
        assert!(load("").unwrap().control.is_none());
        let ctl = |extra: &str| {
            format!(
                "control:\n  listen_addr: 0.0.0.0:7443\n  cert: /c\n  key: /k\n  client_ca: /ca\n  command_signing_key: /s.key\n{extra}"
            )
        };
        let c = load(&ctl("")).unwrap().control.unwrap();
        assert_eq!(
            (
                c.max_connections,
                c.max_connections_per_ip,
                c.command_timeout_secs
            ),
            (1024, 16, 30)
        );
        assert!(c.revoked_hosts.is_empty());
        assert!(load(&ctl("  command_timeout_secs: 0\n")).is_err());
        assert!(load(&ctl("  command_timeout_secs: 111\n")).is_err());
        assert!(load(&ctl("  command_timeout_secs: 110\n")).is_ok());
        assert!(load(&ctl("  max_connections: 0\n")).is_err());
        assert!(load(&ctl("  max_connections_per_ip: 0\n")).is_err());
    }

    #[test]
    fn control_reserved_caps_are_accepted_and_validated_but_not_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let load = |body: &str| {
            std::fs::write(
                &path,
                format!("db_path: /e\nspool_path: /s\nlisten_addr: 127.0.0.1:8080\nrules_dir: /r\ncontrol:\n{body}"),
            )
            .unwrap();
            ServerConfig::load(&path)
        };
        let ok = "  listen_addr: 0.0.0.0:7443\n  cert: /c\n  key: /k\n  client_ca: /ca\n  command_signing_key: /s\n";
        let c = load(&format!(
            "{ok}  max_connections: 5\n  max_connections_per_ip: 2\n"
        ))
        .unwrap()
        .control
        .unwrap();
        assert_eq!((c.max_connections, c.max_connections_per_ip), (5, 2));
        let err = load(&format!("{ok}  max_connections: 0\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn control_rejects_empty_paths_and_bad_listen_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        let load = |addr: &str, cert: &str, key: &str, ca: &str, sk: &str| {
            std::fs::write(
                &path,
                format!("db_path: /e\nspool_path: /s\nlisten_addr: 127.0.0.1:8080\nrules_dir: /r\ncontrol:\n  listen_addr: {addr}\n  cert: \"{cert}\"\n  key: \"{key}\"\n  client_ca: \"{ca}\"\n  command_signing_key: \"{sk}\"\n"),
            )
            .unwrap();
            ServerConfig::load(&path)
        };
        assert!(load("0.0.0.0:1", "/c", "/k", "/ca", "/s").is_ok());
        assert!(load("0.0.0.0:1", "", "/k", "/ca", "/s").is_err());
        assert!(load("0.0.0.0:1", "/c", "", "/ca", "/s").is_err());
        assert!(load("0.0.0.0:1", "/c", "/k", "", "/s").is_err());
        assert!(load("0.0.0.0:1", "/c", "/k", "/ca", "").is_err());
        assert!(load("not-an-addr", "/c", "/k", "/ca", "/s").is_err());
    }
}
