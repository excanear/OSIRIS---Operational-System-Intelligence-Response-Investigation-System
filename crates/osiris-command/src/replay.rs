use crate::guard::Refusal;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

const PRUNE_GRACE_MS: u64 = 60_000;

struct Inner {
    seen: HashMap<Uuid, u64>,
    file: File,
}

/// Durable set of seen command ids. One line per id: `<uuid> <expires_at_ms>\n`.
pub struct ReplayStore {
    inner: Mutex<Inner>,
}

impl ReplayStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut seen = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if let (Some(id), Some(exp)) = (it.next(), it.next()) {
                    if let (Ok(id), Ok(exp)) = (id.parse::<Uuid>(), exp.parse::<u64>()) {
                        seen.insert(id, exp);
                    }
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner: Mutex::new(Inner { seen, file }),
        })
    }

    /// Records the id durably (fsync) before returning `Ok`.
    pub fn check_and_record(
        &self,
        id: Uuid,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), Refusal> {
        let mut g = self.inner.lock().expect("replay lock");
        g.seen
            .retain(|_, exp| exp.saturating_add(PRUNE_GRACE_MS) >= now_ms);
        if g.seen.contains_key(&id) {
            return Err(Refusal::Replay);
        }
        // Fail closed: if we cannot persist the id we must not execute.
        writeln!(g.file, "{id} {expires_at_ms}")
            .and_then(|_| g.file.sync_data())
            .map_err(|_| Refusal::Replay)?;
        g.seen.insert(id, expires_at_ms);
        Ok(())
    }
}
