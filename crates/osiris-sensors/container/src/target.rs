use std::path::PathBuf;

use osiris_fileutil::container_id_from_cgroup_path;
use serde::Deserialize;

/// One config-declared cgroup directory to scan for container cgroups
/// (Phase 5 plan Task 5) — a real deployment configures one or more of
/// `/sys/fs/cgroup/system.slice` (dockerd/containerd via the systemd
/// cgroup driver) and `/sys/fs/cgroup/kubepods.slice` (Kubernetes).
/// Explicit, never auto-discovered: an operator who points this at the
/// wrong directory gets exactly what they configured, matching
/// `PersistenceWatchTarget`'s own precedent.
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerCgroupRoot {
    pub path: String,
}

/// Lists the immediate subdirectories of `root.path` whose name resolves
/// to a container id via `container_id_from_cgroup_path` (plan Global
/// Constraint #5). Non-recursive, matching `candidate_paths`' own
/// plan-scoped-minimalism precedent — container cgroups live one level
/// under a known slice directory. A root that doesn't exist yet yields no
/// candidates, not an error (same "not-yet-created is ordinary" reasoning
/// `PersistenceWatchTarget::candidate_paths` already established).
pub fn candidate_container_dirs(root: &ContainerCgroupRoot) -> Vec<PathBuf> {
    let path = PathBuf::from(&root.path);
    std::fs::read_dir(&path)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(container_id_from_cgroup_path)
                .is_some()
        })
        .collect()
}

/// The container id a discovered cgroup directory belongs to, derived
/// from its directory name.
pub fn container_id_for_dir(dir: &std::path::Path) -> Option<String> {
    dir.file_name()
        .and_then(|n| n.to_str())
        .and_then(container_id_from_cgroup_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64() -> String {
        "9".repeat(64)
    }

    #[test]
    fn finds_a_docker_scope_directory_and_ignores_non_container_ones() {
        let dir = tempfile::tempdir().unwrap();
        let id = hex64();
        std::fs::create_dir(dir.path().join(format!("docker-{id}.scope"))).unwrap();
        std::fs::create_dir(dir.path().join("init.scope")).unwrap();
        let root = ContainerCgroupRoot {
            path: dir.path().to_string_lossy().to_string(),
        };
        let found = candidate_container_dirs(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(container_id_for_dir(&found[0]), Some(id));
    }

    #[test]
    fn a_root_that_does_not_exist_yields_no_candidates() {
        let root = ContainerCgroupRoot {
            path: "/does/not/exist".to_string(),
        };
        assert!(candidate_container_dirs(&root).is_empty());
    }
}
