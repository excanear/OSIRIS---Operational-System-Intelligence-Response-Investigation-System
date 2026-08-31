use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::EntityRef;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entry::{ActorRef, AuditEntry, AuditResult, NewAuditEntry};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000"; // 64 hex chars, matches SHA-256 output width

#[derive(Debug, thiserror::Error)]
pub enum AuditLogError {
    #[error("failed to open audit log at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read audit log at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to deserialize audit entry from {path}: {source}")]
    ReadEntry {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write audit entry: {0}")]
    Write(#[from] std::io::Error),
    #[error("failed to serialize/deserialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("audit chain broken at entry {audit_id}: expected hash {expected}, found {found}")]
    ChainBroken {
        audit_id: Uuid,
        expected: String,
        found: String,
    },
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
///
/// Single-writer-per-path: this type provides no cross-process locking
/// (only an in-process Mutex). If two FileAuditLog instances — in the same
/// or different processes — hold the same path open and both call
/// `append` concurrently, the hash chain can silently fork (both read the
/// same tail hash before either writes). ARCHITECTURE.md §22 describes
/// osiris-audit as used by both the Agent and Server processes; a later
/// phase must either give each process its own audit log file, or add
/// real cross-process locking (e.g. O_APPEND + advisory flock) before two
/// processes share one path.
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
            .map_err(|source| AuditLogError::Open {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    fn last_hash(&self) -> Result<String, AuditLogError> {
        let entries = self.read_all()?;
        Ok(entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    /// Hashes `bytes` prefixed with its own length (as a fixed-width
    /// little-endian u64), so that two different splits of a concatenated
    /// byte stream (e.g. `what="config_"` + `target="reload"` vs.
    /// `what="config"` + `target="_reload"`) never hash identically. See
    /// `compute_hash` for the full rationale.
    fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    /// Computes the SHA-256 hash for one audit entry, chaining in the
    /// previous entry's hash.
    ///
    /// Every variable-length field is hashed via [`Self::hash_field`],
    /// which prepends the byte length before the bytes themselves. Without
    /// this, naively concatenating fields (`prev || who || what || target
    /// || why || result`) would let an attacker with write access to the
    /// log shift text across a field boundary — e.g. `what="config_"` +
    /// `target="reload"` would hash identically to `what="config"` +
    /// `target="_reload"` — without changing the digest, defeating
    /// tamper detection.
    ///
    /// `why` additionally hashes an explicit 1-byte presence discriminant
    /// (0 for `None`, 1 for `Some`) before its length-prefixed bytes, so
    /// that `why: None` and `why: Some("")` — a missing justification vs.
    /// an empty one for a destructive action, per ARCHITECTURE.md §13/§22
    /// — are never hash-collidable with each other.
    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        prev_entry_hash: &str,
        audit_id: Uuid,
        timestamp: u64,
        who: &ActorRef,
        what: &str,
        target: &EntityRef,
        why: &Option<String>,
        result: AuditResult,
    ) -> String {
        let mut hasher = Sha256::new();
        Self::hash_field(&mut hasher, prev_entry_hash.as_bytes());
        hasher.update(audit_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        Self::hash_field(&mut hasher, &serde_json::to_vec(who).unwrap_or_default());
        Self::hash_field(&mut hasher, what.as_bytes());
        Self::hash_field(&mut hasher, &serde_json::to_vec(target).unwrap_or_default());
        match why {
            Some(w) => {
                hasher.update([1u8]);
                Self::hash_field(&mut hasher, w.as_bytes());
            }
            None => {
                hasher.update([0u8]);
            }
        }
        Self::hash_field(
            &mut hasher,
            &serde_json::to_vec(&result).unwrap_or_default(),
        );
        hex::encode(hasher.finalize())
    }
}

impl AuditLog for FileAuditLog {
    fn append(&self, new_entry: NewAuditEntry) -> Result<AuditEntry, AuditLogError> {
        let _guard = self.lock.lock().unwrap();
        let prev_entry_hash = self.last_hash()?;
        let audit_id = Uuid::now_v7();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let entry_hash = Self::compute_hash(
            &prev_entry_hash,
            audit_id,
            timestamp,
            &new_entry.who,
            &new_entry.what,
            &new_entry.target,
            &new_entry.why,
            new_entry.result,
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
            .map_err(|source| AuditLogError::Open {
                path: self.path.clone(),
                source,
            })?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(entry)
    }

    fn read_all(&self) -> Result<Vec<AuditEntry>, AuditLogError> {
        let file = File::open(&self.path).map_err(|source| AuditLogError::Open {
            path: self.path.clone(),
            source,
        })?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|source| AuditLogError::Read {
                path: self.path.clone(),
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(&line).map_err(|source| {
                AuditLogError::ReadEntry {
                    path: self.path.clone(),
                    source,
                }
            })?);
        }
        Ok(entries)
    }

    /// Verifies the hash chain's internal consistency: detects any modification
    /// to a stored entry's fields, and detects reordering (since each entry's
    /// prev_entry_hash must match its predecessor's entry_hash). Does NOT detect
    /// truncation — deleting the most recent N entries from the file produces a
    /// chain that still verifies successfully from genesis, since nothing in
    /// the file records the expected chain length or a sealed head. Does NOT
    /// prevent a full log rewrite by an attacker with write access to the file,
    /// since the chain is unkeyed (anyone can recompute it from genesis) —
    /// this matches ARCHITECTURE.md §17.2's acknowledgment that the audit
    /// mechanism is "not preventable at the OS level alone." A future phase
    /// should add a separately-persisted head pointer/entry count to close the
    /// truncation gap.
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
                &entry.prev_entry_hash,
                entry.audit_id,
                entry.timestamp,
                &entry.who,
                &entry.what,
                &entry.target,
                &entry.why,
                entry.result,
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
            target: EntityRef::Domain {
                name: "agent.yaml".to_string(),
            },
            why: None,
            result: AuditResult::Success,
        })
        .unwrap();
        log.append(NewAuditEntry {
            who: ActorRef::User {
                user_id: Uuid::new_v4(),
            },
            what: "rule_disable".to_string(),
            target: EntityRef::Domain {
                name: "rule:suspicious_execution_chain".to_string(),
            },
            why: Some("false positive under investigation".to_string()),
            result: AuditResult::Success,
        })
        .unwrap();

        assert!(log.verify_chain().is_ok());
        assert_eq!(log.read_all().unwrap().len(), 2);
    }

    #[test]
    fn tampered_entry_breaks_verification() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: EntityRef::Domain {
                name: "agent.yaml".to_string(),
            },
            why: None,
            result: AuditResult::Success,
        })
        .unwrap();

        let path = dir.path().join("audit.jsonl");
        let contents = std::fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("config_reload", "config_wipe");
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(
            log.verify_chain(),
            Err(AuditLogError::ChainBroken { .. })
        ));
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
            target: EntityRef::Domain {
                name: "agent.yaml".to_string(),
            },
            why: None,
            result: AuditResult::Success,
        })
        .unwrap();

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
        assert!(
            err_msg.contains(&path_str.to_string()),
            "error message should include path, got: {}",
            err_msg
        );
    }

    #[test]
    fn read_entry_error_includes_path_context() {
        let (dir, log) = temp_log();
        log.append(NewAuditEntry {
            who: ActorRef::System,
            what: "config_reload".to_string(),
            target: EntityRef::Domain {
                name: "agent.yaml".to_string(),
            },
            why: None,
            result: AuditResult::Success,
        })
        .unwrap();

        let path = dir.path().join("audit.jsonl");
        // Write corrupted JSON to trigger parse error
        std::fs::write(&path, "invalid json").unwrap();

        let err = log.read_all();
        let is_read_entry_err = matches!(err, Err(AuditLogError::ReadEntry { .. }));
        assert!(
            is_read_entry_err,
            "expected ReadEntry error, got: {:?}",
            err
        );

        // Verify path is in the error message
        if let Err(AuditLogError::ReadEntry {
            path: err_path,
            source: _,
        }) = err
        {
            assert_eq!(err_path, path, "error should contain the file path");
        } else {
            panic!("expected ReadEntry variant with path");
        }
    }
}
