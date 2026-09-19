use std::collections::HashMap;
use std::path::PathBuf;

use osiris_sensor_api::{PersistenceEventRaw, PersistenceOperation, RawEventSource};
use sha2::{Digest, Sha256};

use crate::target::{candidate_paths, checkpoint_kind_for, PersistenceWatchTarget};

#[derive(Clone)]
struct SeenFile {
    hash: String,
    size: u64,
}

/// Scans every configured `PersistenceWatchTarget` and diffs the result
/// against the previous tick (plan Global Constraint #1: this is the one
/// mechanism that produces BOTH Systemd unit-file-lifecycle events and
/// generic Persistence events — the classification into which is which
/// happens per-file via `checkpoint_kind_for`, not by two separate
/// scanners).
///
/// KNOWN, DELIBERATE BEHAVIOR (plan Global Constraint #8 — NOT the same
/// choice `NetworkPoller` made, and that is intentional): the very first
/// `poll()` call after construction seeds `previous` from whatever it finds
/// and emits NOTHING for it. Only a change observed between tick N and
/// tick N+1, once a first scan has already completed, is ever reported.
pub struct PersistencePoller {
    targets: Vec<PersistenceWatchTarget>,
    previous: HashMap<PathBuf, SeenFile>,
    first_scan_done: bool,
}

impl PersistencePoller {
    pub fn new(targets: Vec<PersistenceWatchTarget>) -> Self {
        Self {
            targets,
            previous: HashMap::new(),
            first_scan_done: false,
        }
    }

    /// One scan tick. Returns every Created/Modified/Removed event since
    /// the previous tick — or, on the very first call, updates internal
    /// state and returns an empty `Vec` unconditionally (Global Constraint
    /// #8).
    pub fn poll(&mut self, now_ns: u64) -> Vec<PersistenceEventRaw> {
        let mut current: HashMap<
            PathBuf,
            (SeenFile, osiris_sensor_api::PersistenceCheckpointKind),
        > = HashMap::new();
        for target in &self.targets {
            for path in candidate_paths(target) {
                let Some(kind) = checkpoint_kind_for(target.kind, &path) else {
                    continue;
                };
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let hash = format!("{:x}", Sha256::digest(&bytes));
                current.insert(
                    path,
                    (
                        SeenFile {
                            hash,
                            size: bytes.len() as u64,
                        },
                        kind,
                    ),
                );
            }
        }

        if !self.first_scan_done {
            self.first_scan_done = true;
            self.previous = current.into_iter().map(|(p, (f, _))| (p, f)).collect();
            return vec![];
        }

        let mut events = Vec::new();
        for (path, (seen, kind)) in &current {
            match self.previous.get(path) {
                None => events.push(make_event(
                    PersistenceOperation::Created,
                    *kind,
                    path,
                    Some(seen.clone()),
                    now_ns,
                )),
                Some(prior) if prior.hash != seen.hash => events.push(make_event(
                    PersistenceOperation::Modified,
                    *kind,
                    path,
                    Some(seen.clone()),
                    now_ns,
                )),
                Some(_) => {}
            }
        }
        for path in self.previous.keys() {
            if !current.contains_key(path) {
                // The removed file's checkpoint kind is no longer
                // discoverable from `current` (it's gone) — but every
                // target this poller was ever configured with is still in
                // `self.targets`, so re-derive it the same way `poll`
                // itself does, from whichever target's directory the path
                // lived under.
                if let Some(kind) = self.targets.iter().find_map(|t| {
                    if path.starts_with(&t.path) {
                        checkpoint_kind_for(t.kind, path)
                    } else {
                        None
                    }
                }) {
                    events.push(make_event(
                        PersistenceOperation::Removed,
                        kind,
                        path,
                        None,
                        now_ns,
                    ));
                }
            }
        }

        self.previous = current.into_iter().map(|(p, (f, _))| (p, f)).collect();
        events
    }
}

fn make_event(
    operation: PersistenceOperation,
    checkpoint_kind: osiris_sensor_api::PersistenceCheckpointKind,
    path: &std::path::Path,
    seen: Option<SeenFile>,
    now_ns: u64,
) -> PersistenceEventRaw {
    PersistenceEventRaw {
        operation,
        checkpoint_kind,
        path: path.to_string_lossy().to_string(),
        content_hash: seen.as_ref().map(|s| s.hash.clone()),
        size: seen.as_ref().map(|s| s.size),
        timestamp_ns: now_ns,
        source: RawEventSource::Procfs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::PersistenceWatchKind;

    fn unit_dir_target(path: &std::path::Path) -> PersistenceWatchTarget {
        PersistenceWatchTarget {
            path: path.to_string_lossy().to_string(),
            kind: PersistenceWatchKind::SystemdUnitDir,
        }
    }

    #[test]
    fn the_first_poll_seeds_a_baseline_and_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("preexisting.service"), "x").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
    }

    #[test]
    fn a_file_created_after_the_first_scan_emits_created() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::write(dir.path().join("backdoor.service"), "malicious").unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Created);
        assert_eq!(
            events[0].checkpoint_kind,
            osiris_sensor_api::PersistenceCheckpointKind::SystemdUnit
        );
        assert!(events[0].path.ends_with("backdoor.service"));
        assert!(events[0].content_hash.is_some());
    }

    #[test]
    fn a_file_whose_content_changes_emits_modified_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("existing.service");
        std::fs::write(&file, "v1").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::write(&file, "v2 - changed").unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Modified);
    }

    #[test]
    fn a_file_that_disappears_emits_removed_with_no_hash() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("temporary.service");
        std::fs::write(&file, "x").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::remove_file(&file).unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, PersistenceOperation::Removed);
        assert!(events[0].content_hash.is_none());
        assert!(events[0].size.is_none());
    }

    #[test]
    fn an_unchanged_file_emits_nothing_on_the_second_poll() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stable.service"), "same").unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        assert!(poller.poll(2_000).is_empty());
    }

    /// A `.socket` file in a unit dir is never a candidate at all (plan
    /// Global Constraint #4), so it must never surface as any kind of
    /// event, even though the real filesystem entry exists throughout.
    #[test]
    fn an_unrecognized_extension_in_a_unit_dir_is_never_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = PersistencePoller::new(vec![unit_dir_target(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        std::fs::write(dir.path().join("ignored.socket"), "x").unwrap();
        assert!(poller.poll(2_000).is_empty());
    }
}
