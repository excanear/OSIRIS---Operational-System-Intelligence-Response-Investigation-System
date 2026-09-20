use crate::guard::Refusal;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

const PRUNE_GRACE_MS: u64 = 60_000;

fn parse_line(buf: &[u8]) -> Option<(Uuid, u64)> {
    let line = std::str::from_utf8(buf).ok()?;
    if !line.ends_with('\n') {
        return None; // torn final line
    }
    let mut it = line.split_whitespace();
    let id = it.next()?.parse::<Uuid>().ok()?;
    let exp = it.next()?.parse::<u64>().ok()?;
    Some((id, exp))
}

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
        let mut reader = match File::open(path) {
            Ok(f) => Some(std::io::BufReader::new(f)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some(r) = reader.as_mut() {
            let mut buf = Vec::new();
            loop {
                buf.clear();
                if r.read_until(b'\n', &mut buf)? == 0 {
                    break;
                }
                // Malformed or torn lines are skipped; they never discard other entries.
                if let Some((id, exp)) = parse_line(&buf) {
                    seen.insert(id, exp);
                }
            }
        } else {
            // no file yet: empty store
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn torn_non_utf8_last_line_keeps_earlier_ids() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "{} 100", id(1)).unwrap();
        writeln!(f, "{} 100", id(2)).unwrap();
        f.write_all(b"0000\xff\xfe").unwrap();
        drop(f);
        let s = ReplayStore::open(&p).unwrap();
        assert_eq!(s.check_and_record(id(1), 100, 0), Err(Refusal::Replay));
        assert_eq!(s.check_and_record(id(2), 100, 0), Err(Refusal::Replay));
    }

    #[test]
    fn unreadable_path_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        assert!(ReplayStore::open(d.path()).is_err());
    }

    #[test]
    fn garbage_middle_line_does_not_drop_later_entries() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "{} 100", id(1)).unwrap();
        f.write_all(b"garbage\xff line\n").unwrap();
        writeln!(f, "{} 100", id(3)).unwrap();
        drop(f);
        let s = ReplayStore::open(&p).unwrap();
        assert_eq!(s.check_and_record(id(1), 100, 0), Err(Refusal::Replay));
        assert_eq!(s.check_and_record(id(3), 100, 0), Err(Refusal::Replay));
    }
}
