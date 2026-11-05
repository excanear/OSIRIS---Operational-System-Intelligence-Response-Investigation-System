//! Opens the configured telemetry `Storage` backend (Phase 11c).
//!
//! SQLite is the default. A configured-but-unusable ClickHouse is an error,
//! never a silent fallback to SQLite.

use std::sync::Arc;
use std::time::Duration;

use osiris_storage::Storage;
use osiris_storage_clickhouse::{redacted_url, ClickHouseOptions, ClickHouseStorage};
use osiris_storage_sqlite::SqliteStorage;

use crate::config::{ServerConfig, StorageBackend};

/// Opens the backend `config` selects. The error text names the backend and
/// its location, and never contains the ClickHouse password.
pub fn open_storage(config: &ServerConfig) -> Result<Arc<dyn Storage>, String> {
    match config.storage_backend {
        StorageBackend::Sqlite => SqliteStorage::open(&config.db_path)
            .map(|s| Arc::new(s) as Arc<dyn Storage>)
            .map_err(|e| format!("sqlite storage at {}: {e}", config.db_path)),
        StorageBackend::Clickhouse => {
            let ch = config
                .clickhouse
                .as_ref()
                .ok_or("storage_backend clickhouse requires a clickhouse section")?;
            let password = match &ch.password_file {
                Some(path) => {
                    let raw = std::fs::read_to_string(path).map_err(|e| {
                        format!("clickhouse password file {path} could not be read: {e}")
                    })?;
                    Some(raw.trim_end_matches(['\r', '\n']).to_string())
                }
                None => None,
            };
            let opts = ClickHouseOptions {
                url: ch.url.clone(),
                database: ch.database.clone(),
                user: ch.user.clone(),
                password,
                timeout: Duration::from_secs(ch.timeout_secs),
            };
            ClickHouseStorage::open(opts)
                .map(|s| Arc::new(s) as Arc<dyn Storage>)
                // Only scheme://host:port: the raw url may carry credentials.
                .map_err(|e| format!("clickhouse storage at {}: {e}", redacted_url(&ch.url)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str, db_path: &str) -> ServerConfig {
        serde_yaml::from_str(&format!(
            "db_path: \"{db_path}\"\nspool_path: /s\nlisten_addr: 127.0.0.1:8080\nrules_dir: /r\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn sqlite_backend_opens_db_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("events.db");
        let cfg = config("", &db.to_string_lossy().replace('\\', "/"));
        assert!(open_storage(&cfg).is_ok());
    }

    #[test]
    fn clickhouse_backend_unreachable_is_an_error_not_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("events.db");
        let cfg = config(
            "storage_backend: clickhouse\nclickhouse:\n  url: http://127.0.0.1:1\n  timeout_secs: 1\n",
            &db.to_string_lossy().replace('\\', "/"),
        );
        let err = open_storage(&cfg).err().expect("must fail");
        assert!(err.to_lowercase().contains("clickhouse"), "{err}");
        assert!(!db.exists(), "must not fall back to SQLite");
    }

    #[test]
    fn open_errors_never_contain_url_credentials() {
        for url in [
            "http://u:s3cr3t@127.0.0.1:1",
            "http://127.0.0.1:1/?user=u&password=s3cr3t",
        ] {
            let cfg = config(
                &format!(
                    "storage_backend: clickhouse\nclickhouse:\n  url: \"{url}\"\n  timeout_secs: 1\n"
                ),
                "/tmp/e.db",
            );
            let err = open_storage(&cfg).err().expect("must fail");
            assert!(!err.contains("s3cr3t"), "{url}: {err}");
            assert!(err.contains("127.0.0.1:1"), "{url}: {err}");
        }
    }

    #[test]
    fn missing_password_file_is_an_error_naming_the_path() {
        let cfg = config(
            "storage_backend: clickhouse\nclickhouse:\n  url: http://127.0.0.1:1\n  password_file: /nonexistent/ch-password\n",
            "/tmp/e.db",
        );
        let err = open_storage(&cfg).err().expect("must fail");
        assert!(err.contains("/nonexistent/ch-password"), "{err}");
    }
}
