//! Exit-time `exe_path` cache.
//!
//! An exit record arrives after the process is gone, so `/proc/<pid>/exe`
//! cannot be read. The exec record's resolved `exe_path` is remembered under
//! `(tgid, start_boottime_ns)` — the start time distinguishes a recycled pid
//! — and taken back when the matching exit arrives. The cache is bounded
//! ([`EXE_CACHE_CAPACITY`]); when full the oldest insert is evicted, so a
//! process that outlives 65 536 later execs exits with an empty `exe_path`.

use std::collections::{HashMap, VecDeque};

/// Entries kept before the oldest insert is evicted.
pub const EXE_CACHE_CAPACITY: usize = 65_536;

type Key = (u32, u64);

/// Bounded `(tgid, start_boottime_ns)` → `exe_path` map, oldest-insert-first
/// eviction.
#[derive(Debug)]
pub struct ExeCache {
    capacity: usize,
    /// Key → (insertion sequence, path).
    map: HashMap<Key, (u64, String)>,
    /// Insertion order. Holds stale entries (taken or re-inserted keys,
    /// recognised by a sequence that no longer matches the map's); they are
    /// skipped on eviction and swept when the queue outgrows the bound.
    order: VecDeque<(Key, u64)>,
    next_seq: u64,
}

impl ExeCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
        }
    }

    /// Remember `exe_path`; evicts the oldest insert when full. Re-inserting
    /// a key replaces its value and counts as a fresh insert.
    pub fn insert(&mut self, tgid: u32, start_boottime_ns: u64, exe_path: String) {
        if self.capacity == 0 {
            return;
        }
        let key = (tgid, start_boottime_ns);
        if !self.map.contains_key(&key) {
            while self.map.len() >= self.capacity {
                let Some((old, seq)) = self.order.pop_front() else {
                    break;
                };
                if self.map.get(&old).is_some_and(|(s, _)| *s == seq) {
                    self.map.remove(&old);
                }
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.map.insert(key, (seq, exe_path));
        self.order.push_back((key, seq));
        if self.order.len() > self.capacity.saturating_mul(2) {
            let map = &self.map;
            self.order
                .retain(|(k, s)| map.get(k).is_some_and(|(cur, _)| cur == s));
        }
    }

    /// Remove and return the path for this process, `None` on a miss.
    pub fn take(&mut self, tgid: u32, start_boottime_ns: u64) -> Option<String> {
        self.map
            .remove(&(tgid, start_boottime_ns))
            .map(|(_, path)| path)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_cache_miss_and_eviction() {
        let mut c = ExeCache::new(2);
        assert_eq!(c.take(1, 1), None);
        c.insert(1, 10, "/a".into());
        c.insert(2, 20, "/b".into());
        c.insert(3, 30, "/c".into());
        assert_eq!(c.take(1, 10), None);
        assert_eq!(c.take(3, 30), Some("/c".to_string()));
        // take removes the entry.
        assert_eq!(c.take(3, 30), None);
        assert_eq!(c.take(2, 20), Some("/b".to_string()));
    }

    #[test]
    fn reinsert_updates_without_duplicates_and_queue_stays_bounded() {
        let mut c = ExeCache::new(2);
        c.insert(1, 1, "/old".into());
        c.insert(1, 1, "/new".into());
        c.insert(2, 2, "/b".into());
        assert_eq!(c.len(), 2);
        assert_eq!(c.take(1, 1), Some("/new".to_string()));
        // Many exec/exit pairs never grow the queue past 2x capacity + 1.
        for i in 0..100u32 {
            c.insert(i, 5, "/x".into());
            c.take(i, 5);
        }
        assert!(c.order.len() <= 5);
        // A taken-then-reinserted key is not evicted by its stale entry.
        let mut c = ExeCache::new(2);
        c.insert(1, 1, "/a".into());
        c.take(1, 1);
        c.insert(1, 1, "/a2".into());
        c.insert(2, 2, "/b".into());
        assert_eq!(c.take(1, 1), Some("/a2".to_string()));
        assert_eq!(c.take(2, 2), Some("/b".to_string()));
    }
}
