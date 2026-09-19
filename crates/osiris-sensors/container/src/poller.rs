use std::collections::HashSet;

use osiris_sensor_api::{ContainerEventRaw, ContainerOperation, RawEventSource};

use crate::target::{candidate_container_dirs, container_id_for_dir, ContainerCgroupRoot};

/// Scans every configured `ContainerCgroupRoot` and diffs the result
/// against the previous tick (Phase 5 plan Task 5, mirroring
/// `PersistencePoller`'s own scan-and-diff shape). A cgroup directory
/// appearing emits `Create` immediately followed by `Start`; one
/// disappearing emits `Stop` immediately followed by `Destroy` (plan
/// Global Constraint #7's disclosed transition-pairing — a poll-based
/// scanner cannot distinguish "just created" from "just started", or
/// "asked to stop" from "fully torn down", between ticks).
///
/// Same first-tick-seeds-a-silent-baseline behavior as `PersistencePoller`
/// (plan Global Constraint #7 continues that precedent): whatever
/// containers are already running when the Agent starts are not reported
/// as newly created.
pub struct ContainerCgroupPoller {
    roots: Vec<ContainerCgroupRoot>,
    previous: HashSet<String>,
    first_scan_done: bool,
}

impl ContainerCgroupPoller {
    pub fn new(roots: Vec<ContainerCgroupRoot>) -> Self {
        Self {
            roots,
            previous: HashSet::new(),
            first_scan_done: false,
        }
    }

    /// One scan tick. Returns every lifecycle transition since the
    /// previous tick — or, on the very first call, seeds internal state
    /// and returns an empty `Vec` unconditionally.
    pub fn poll(&mut self, now_ns: u64) -> Vec<ContainerEventRaw> {
        let mut current: HashSet<String> = HashSet::new();
        let mut cgroup_paths: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut cgroup_pids: std::collections::HashMap<String, Option<u32>> =
            std::collections::HashMap::new();
        for root in &self.roots {
            for dir in candidate_container_dirs(root) {
                let Some(container_id) = container_id_for_dir(&dir) else {
                    continue;
                };
                cgroup_paths.insert(container_id.clone(), dir.to_string_lossy().to_string());
                cgroup_pids.insert(container_id.clone(), read_cgroup_procs_pid(&dir));
                current.insert(container_id);
            }
        }

        if !self.first_scan_done {
            self.first_scan_done = true;
            self.previous = current;
            return vec![];
        }

        let mut events = Vec::new();
        for container_id in current.difference(&self.previous) {
            let cgroup_path = cgroup_paths.get(container_id).cloned().unwrap_or_default();
            let pid = cgroup_pids.get(container_id).copied().flatten();
            events.push(make_event(
                ContainerOperation::Create,
                container_id,
                &cgroup_path,
                pid,
                now_ns,
            ));
            events.push(make_event(
                ContainerOperation::Start,
                container_id,
                &cgroup_path,
                pid,
                now_ns,
            ));
        }
        for container_id in self.previous.difference(&current) {
            events.push(make_event(
                ContainerOperation::Stop,
                container_id,
                "",
                None,
                now_ns,
            ));
            events.push(make_event(
                ContainerOperation::Destroy,
                container_id,
                "",
                None,
                now_ns,
            ));
        }

        self.previous = current;
        events
    }
}

fn make_event(
    operation: ContainerOperation,
    container_id: &str,
    cgroup_path: &str,
    pid: Option<u32>,
    now_ns: u64,
) -> ContainerEventRaw {
    ContainerEventRaw {
        operation,
        container_id: container_id.to_string(),
        image: String::new(),
        runtime: "cgroup".to_string(),
        cgroup_path: cgroup_path.to_string(),
        pid,
        pod_name: None,
        pod_namespace: None,
        timestamp_ns: now_ns,
        source: RawEventSource::Procfs,
    }
}

/// Reads a cgroup directory's `cgroup.procs` file (the real Linux cgroup
/// v2 ABI: a newline-separated list of member pids) and returns the first
/// one, when present — the closest thing to "who's inside this container
/// right now" the cgroup-only fallback backend can honestly report
/// (plan Task 5/Global Constraint #1: no live runtime API to ask instead).
/// `None` when the file is absent (a synthetic/test-fixture cgroup
/// directory, or a real one queried in the narrow race window before any
/// process has joined it) or unparseable — never a fabricated pid.
fn read_cgroup_procs_pid(dir: &std::path::Path) -> Option<u32> {
    let contents = std::fs::read_to_string(dir.join("cgroup.procs")).ok()?;
    contents.lines().next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn root(dir: &std::path::Path) -> ContainerCgroupRoot {
        ContainerCgroupRoot {
            path: dir.to_string_lossy().to_string(),
        }
    }

    #[test]
    fn the_first_poll_seeds_a_baseline_and_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(format!("docker-{}.scope", hex64('a')))).unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
    }

    #[test]
    fn a_container_cgroup_created_after_the_first_scan_emits_create_then_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        let id = hex64('b');
        std::fs::create_dir(dir.path().join(format!("docker-{id}.scope"))).unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation, ContainerOperation::Create);
        assert_eq!(events[0].container_id, id);
        assert_eq!(events[1].operation, ContainerOperation::Start);
        assert_eq!(events[1].container_id, id);
        assert!(events[0].cgroup_path.contains(&id));
    }

    #[test]
    fn a_container_cgroup_removed_emits_stop_then_destroy() {
        let dir = tempfile::tempdir().unwrap();
        let id = hex64('c');
        let cgroup_dir = dir.path().join(format!("docker-{id}.scope"));
        std::fs::create_dir(&cgroup_dir).unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::remove_dir(&cgroup_dir).unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation, ContainerOperation::Stop);
        assert_eq!(events[0].container_id, id);
        assert_eq!(events[1].operation, ContainerOperation::Destroy);
        assert_eq!(events[1].container_id, id);
    }

    #[test]
    fn an_unchanged_container_cgroup_emits_nothing_on_the_second_poll() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(format!("docker-{}.scope", hex64('d')))).unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        assert!(poller.poll(2_000).is_empty());
    }

    #[test]
    fn a_created_container_reports_the_pid_from_cgroup_procs_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        let id = hex64('e');
        let cgroup_dir = dir.path().join(format!("docker-{id}.scope"));
        std::fs::create_dir(&cgroup_dir).unwrap();
        std::fs::write(cgroup_dir.join("cgroup.procs"), "4242\n5555\n").unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events[0].pid, Some(4242));
        assert_eq!(events[1].pid, Some(4242));
    }

    #[test]
    fn a_created_container_with_no_cgroup_procs_file_reports_no_pid() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());

        std::fs::create_dir(dir.path().join(format!("docker-{}.scope", hex64('f')))).unwrap();
        let events = poller.poll(2_000);
        assert_eq!(events[0].pid, None);
    }

    #[test]
    fn a_non_container_cgroup_directory_is_never_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut poller = ContainerCgroupPoller::new(vec![root(dir.path())]);
        assert!(poller.poll(1_000).is_empty());
        std::fs::create_dir(dir.path().join("init.scope")).unwrap();
        assert!(poller.poll(2_000).is_empty());
    }
}
