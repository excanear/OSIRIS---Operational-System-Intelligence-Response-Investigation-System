use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum HostIdentityError {
    #[error("failed to read host_id file at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write host_id file at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("host_id file at {path} does not contain a valid UUID: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: uuid::Error,
    },
}

/// Loads the stable per-installation host_id from disk, generating and
/// persisting a new one on first run. ARCHITECTURE.md §9.2: "persisted in
/// /etc/osiris/host_id" (path is caller-supplied here, not hardcoded, so
/// tests and non-default installs can point elsewhere).
pub struct HostIdentity;

impl HostIdentity {
    pub fn load_or_create(path: &Path) -> Result<Uuid, HostIdentityError> {
        if path.exists() {
            let contents = fs::read_to_string(path).map_err(|source| HostIdentityError::Read {
                path: path.to_path_buf(),
                source,
            })?;
            Uuid::parse_str(contents.trim()).map_err(|source| HostIdentityError::Parse {
                path: path.to_path_buf(),
                source,
            })
        } else {
            let id = Uuid::new_v4();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|source| HostIdentityError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
            }
            fs::write(path, id.to_string()).map_err(|source| HostIdentityError::Write {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_persists_host_id_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_id");
        let first = HostIdentity::load_or_create(&path).unwrap();
        let second = HostIdentity::load_or_create(&path).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_corrupted_host_id_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host_id");
        std::fs::write(&path, "not-a-uuid").unwrap();
        let result = HostIdentity::load_or_create(&path);
        assert!(matches!(result, Err(HostIdentityError::Parse { .. })));
    }
}
