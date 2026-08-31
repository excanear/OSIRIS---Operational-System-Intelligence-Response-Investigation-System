use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entry::{ActorRef, AuditEntry, AuditResult, NewAuditEntry};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000"; // 64 hex chars, matches SHA-256 output width

#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    #[error("failed to open audit log at {path}: {source}")]
    Open { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to read audit log at {path}: {source}")]
    Read { path: PathBuf, #[source] source: std::io::Error },
    #[error("failed to deserialize audit entry from {path}: {source}")]
    ReadEntry { path: PathBuf, #[source] source: serde_json::Error },
    #[error("failed to write audit entry: {0}")]
    Write(#[from] std::io::Error),
    #[error("failed to serialize/deserialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("audit chain broken at entry {audit_id}: expected hash {expected}, found {found}")]
    ChainBroken { audit_id: Uuid, expected: String, found: String },
}

pub trait AuditLog {
    fn append(&self, entry: NewAuditEntry) -> Result<AuditEntry, AuditLogError>;
    fn read_all(&self) -> Result<Vec<AuditEntry>, AuditLogError>;
    fn verify_chain(&self) -> Result<(), AuditLogError>;
}

/// Append-only JSONL-backed audit log with a SHA-256 hash chain
/// (ARCHITECTURE.md §22/§17.2). Stands in for the control-plane store's
/// audit table until osiris-storage exists (Phase 1); the `AuditLog` trait
/// is the seam that migration happens behind.
pub struct FileAuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileAuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditLogError> {
        let path = path.into();
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| AuditLogError::Open { path: path.clone(), source })?;
        Ok(Self { path, lock: Mutex::new(()) })
    }

    fn last_hash(&self) -> Result<String, AuditLogError> {
        let entries = self.read_all()?;
        Ok(entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        prev_entry_hash: &str,
        audit_id: Uuid,
        timestamp: u64,
        who: &ActorRef,
        what: &str,
        target: &str,
        why: &Option<String>,
        result: AuditResult,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_entry_hash.as_bytes());
        hasher.update(audit_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(serde_json::to_vec(who).unwrap_or_default());
        hasher.update(what.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(why.clone().unwrap_or_default().as_bytes());
        hasher.update(serde_json::to_vec(&result).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

impl AuditLog for FileAuditLog {
    fn append(&self, new_entry: NewAuditEntry) -> Result<AuditEntry, AuditLogError> {
        let _guard = self.lock.lock().unwrap();
        let prev_entry_hash = self.last_hash()?;
        let audit_id = Uuid::now_v7();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let entry_hash = Self::compute_hash(
            &prev_entry_hash, audit_id, timestamp, &new_entry.who, &new_entry.what,
            &new_entry.target, &new_entry.why, new_entry.result,
        );
        let entry = AuditEntry {
            audit_id,
            timestamp,
            who: new_entry.who,
            what: new_entry.what,
            target: new_entry.target,
            why: new_entry.why,
            result: new_entry.result,
            prev_entry_hash,
            entry_hash,
        };
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| AuditLogError::Open { path: self.path.clone(), source })?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(entry)
    }

    fn read_all(&self) -> Result<Vec<AuditEntry>, AuditLogError> {
        let file = File::open(&self.path)
            .map_err(|source| AuditLogError::Open { path: self.path.clone(), source })?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|source| AuditLogError::Read { path: self.path.clone(), source })?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(&line)
                .map_err(|source| AuditLogError::ReadEntry { path: self.path.clone(), source })?);
        }
        Ok(entries)
    }

    fn verify_chain(&self) -> Result<(), AuditLogError> {
        let entries = self.read_all()?;
        let mut expected_prev = GENESIS_HASH.to_string();
        for entry in &entries {
            if entry.prev_entry_hash != expected_prev {
                return Err(AuditLogError::ChainBroken {
                    audit_id: entry.audit_id,
                    expected: expected_prev,
                    found: entry.prev_entry_hash.clone(),
                });
            }
            let recomputed = Self::compute_hash(
                &entry.prev_entry_hash, entry.audit_id, entry.timestamp, &entry.who,
                &entry.what, &entry.target, &entry.why, entry.result,
            );
            if recomputed != entry.entry_hash {
                return Err(AuditLogError::ChainBroken {
                    audit_id: entry.audit_id,
                    expected: recomputed,
                    found: entry.entry_hash.clone(),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (tempfile::TempDir, FileAuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = FileAuditLog::open(&path).unwrap();
        (dir, log)
    }

    #[test]
    fn appended_entries_form_a_valid_chain() {
        let (_dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();
        log.append(NewAuditEntry {
            who: ActorRef::User { user_id: Uuid::new_v4() },
            what: "rule_disable".to_string(),
            target: "rule:suspicious_execution_chain".to_string(),
            why: Some("false positive under investigation".to_string()),
            result: AuditResult::Success,
        }).unwrap();

        assert!(log.verify_chain().is_ok());
        assert_eq!(log.read_all().unwrap().len(), 2);
    }

    #[test]
    fn tampered_entry_breaks_verification() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();

        let path = dir.path().join("audit.jsonl");
        let contents = std::fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("config_reload", "config_wipe");
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(log.verify_chain(), Err(AuditLogError::ChainBroken { .. })));
    }

    #[test]
    fn empty_log_verifies_trivially() {
        let (_dir, log) = temp_log();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn corrupted_line_produces_contextualized_error() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();

        let path = dir.path().join("audit.jsonl");
        // Corrupt the JSON by truncating it mid-entry
        let contents = std::fs::read_to_string(&path).unwrap();
        let corrupted = contents[..contents.len().saturating_sub(50)].to_string();
        std::fs::write(&path, corrupted).unwrap();

        // read_all should produce a ReadEntry error with path context (JSON parse failure)
        let err = log.read_all();
        let is_read_entry = matches!(err, Err(AuditLogError::ReadEntry { .. }));
        assert!(is_read_entry, "expected ReadEntry error, got: {:?}", err);

        // Verify the error message includes the path
        let err_msg = format!("{}", err.unwrap_err());
        let path_str = path.to_string_lossy();
        assert!(err_msg.contains(&path_str.to_string()),
                "error message should include path, got: {}", err_msg);
    }

    #[test]
    fn read_entry_error_includes_path_context() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: "agent.yaml".to_string(),
            why: None,
            result: AuditResult::Success,
        }).unwrap();

        let path = dir.path().join("audit.jsonl");
        // Write corrupted JSON to trigger parse error
        std::fs::write(&path, "invalid json").unwrap();

        let err = log.read_all();
        let is_read_entry_err = matches!(err, Err(AuditLogError::ReadEntry { .. }));
        assert!(is_read_entry_err, "expected ReadEntry error, got: {:?}", err);

        // Verify path is in the error message
        if let Err(AuditLogError::ReadEntry { path: err_path, source: _ }) = err {
            assert_eq!(err_path, path, "error should contain the file path");
        } else {
            panic!("expected ReadEntry variant with path");
        }
    }
}
