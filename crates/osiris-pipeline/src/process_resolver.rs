use std::collections::HashMap;

use osiris_schema::ProcessKey;

/// In-memory PID→process_key resolver (ARCHITECTURE.md §4.2/§7.1): sensors
/// never cross-reference each other's state directly; the Enrich stage
/// resolves cross-sensor identity through this single resolver instead.
/// Phase 1 scope: maps pid -> (process_key, ppid) so parent_process can be
/// resolved by ppid lookup.
#[derive(Default)]
pub struct ProcessResolver {
    by_pid: HashMap<u32, (ProcessKey, u32)>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `pid` (child of `ppid`) now maps to `process_key`.
    /// Later exec events for the same pid overwrite the mapping (a pid
    /// exec()ing again keeps the same pid but semantically starts a new
    /// image — Phase 1 does not distinguish this from a wholly new
    /// process at the same pid, since PROCESS_FORK is out of scope).
    pub fn record(&mut self, pid: u32, ppid: u32, process_key: ProcessKey) {
        self.by_pid.insert(pid, (process_key, ppid));
    }

    /// Resolves the parent's process_key by looking up this process's own
    /// recorded ppid. Returns None if the parent was never observed (e.g.
    /// it exec'd before the Agent started) — the caller leaves
    /// parent_process unset rather than guessing.
    pub fn resolve_parent(&self, pid: u32) -> Option<ProcessKey> {
        let (_, ppid) = self.by_pid.get(&pid)?;
        self.by_pid.get(ppid).map(|(key, _)| *key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn resolves_parent_when_both_seen() {
        let mut resolver = ProcessResolver::new();
        let host_id = Uuid::new_v4();
        let bash_key = ProcessKey::new(host_id, "boot-1", 100, 1);
        let curl_key = ProcessKey::new(host_id, "boot-1", 200, 2);
        resolver.record(100, 1, bash_key);
        resolver.record(200, 100, curl_key);

        assert_eq!(resolver.resolve_parent(200), Some(bash_key));
    }

    #[test]
    fn returns_none_when_parent_never_observed() {
        let mut resolver = ProcessResolver::new();
        let host_id = Uuid::new_v4();
        let curl_key = ProcessKey::new(host_id, "boot-1", 200, 2);
        resolver.record(200, 999, curl_key);

        assert_eq!(resolver.resolve_parent(200), None);
    }
}
