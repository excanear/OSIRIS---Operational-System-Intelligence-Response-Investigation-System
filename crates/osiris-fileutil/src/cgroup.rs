//! Pure cgroup-file/cgroup-path parsing shared between `osiris-pipeline`
//! (Enrich-stage per-process context resolution, Phase 5 plan Task 3) and
//! `osiris-sensors-container` (the cgroup-scan Container sensor, Phase 5
//! plan Task 5). Lives here rather than in `osiris-pipeline` because a
//! sensor crate must never depend on the pipeline (§27's privilege-boundary
//! direction is sensors -> pipeline via RawEvent only, never the reverse),
//! and `osiris-fileutil` is this codebase's established shared-leaf crate
//! for exactly this kind of cross-crate parsing reuse (the Phase 4b
//! `nested_msg_record`/`split_record` precedent). No OSIRIS-internal
//! dependencies here (enforced by `tools/check-dep-graph.sh`), so this
//! module owns its own minimal `CgroupFileVersion` rather than importing
//! `osiris_schema::CgroupVersion` — each caller maps it to its own richer
//! type.

/// Which cgroup hierarchy shape a `/proc/<pid>/cgroup`-style file's lines
/// took (Phase 5 plan Global Constraint #3). Cgroup v2 (unified hierarchy)
/// prints exactly one line, always `0::<path>`; cgroup v1 (per-controller
/// hierarchy) prints one line per mounted controller, each
/// `<hierarchy-id>:<controllers>:<path>` with a nonzero hierarchy id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupFileVersion {
    V1,
    V2,
}

/// Parses the contents of a `/proc/<pid>/cgroup`-shaped file. Returns the
/// first line's path plus which version the file's shape indicates, or
/// `None` when the content doesn't match either recognized shape (missing
/// file content, empty string, or garbage) — never a fabricated guess.
///
/// v1 files with several controller lines may report different paths per
/// controller (rare, but real, on complex v1 setups); this function
/// returns the *first* line's path, matching the "one path per process"
/// simplification every other resolver in this codebase already makes for
/// less-than-fully-general inputs (e.g. `NetworkEventRaw.proto` staying a
/// string rather than modeling every real-world variant up front).
pub fn parse_cgroup_file(contents: &str) -> Option<(String, CgroupFileVersion)> {
    let mut lines = contents.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next()?;
    let mut parts = first.splitn(3, ':');
    let hierarchy_id = parts.next()?;
    let _controllers = parts.next()?;
    let path = parts.next()?;
    if path.is_empty() {
        return None;
    }
    if hierarchy_id == "0" {
        Some((path.to_string(), CgroupFileVersion::V2))
    } else if hierarchy_id.chars().all(|c| c.is_ascii_digit()) && !hierarchy_id.is_empty() {
        Some((path.to_string(), CgroupFileVersion::V1))
    } else {
        None
    }
}

/// Extracts a container id from a cgroup path using the naming
/// conventions real container runtimes/orchestrators produce (Phase 5 plan
/// Global Constraint #5). Recognizes:
/// - `.../docker-<64-hex>.scope` (dockerd, systemd cgroup driver)
/// - `.../docker/<64-hex>` (dockerd, cgroupfs driver / v1)
/// - `.../cri-containerd-<64-hex>.scope` (containerd, systemd driver)
/// - `.../kubepods*/.../<64-hex>` (any Kubernetes pod's container, either
///   driver — matched by "some path segment is a bare 64-hex id under a
///   `kubepods`-prefixed segment", not a specific depth, since pod QoS
///   class and pod-uid-segment naming vary across kubelet versions)
///
/// A path matching none of these returns `None` — no container context is
/// attached rather than guessed (this codebase's "no edge/identity citing
/// a fabricated value" discipline, applied here to cgroup-derived
/// identity).
pub fn container_id_from_cgroup_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let is_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());

    let mut saw_kubepods = false;
    for segment in &segments {
        if segment.starts_with("kubepods") {
            saw_kubepods = true;
        }
        if let Some(rest) = segment.strip_prefix("docker-") {
            if let Some(id) = rest.strip_suffix(".scope") {
                if is_hex64(id) {
                    return Some(id.to_string());
                }
            }
        }
        if let Some(rest) = segment.strip_prefix("cri-containerd-") {
            if let Some(id) = rest.strip_suffix(".scope") {
                if is_hex64(id) {
                    return Some(id.to_string());
                }
            }
        }
    }
    // `.../docker/<64-hex>` and `.../kubepods*/.../<64-hex>`: a bare
    // hex64 segment, preceded somewhere by `docker` or a `kubepods*`
    // segment.
    for (i, segment) in segments.iter().enumerate() {
        if is_hex64(segment) {
            let preceded_by_docker = i > 0 && segments[i - 1] == "docker";
            if preceded_by_docker || saw_kubepods {
                return Some(segment.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_cgroup_v2_single_line_file() {
        let contents = format!("0::/system.slice/docker-{}.scope\n", "a".repeat(64));
        let (path, version) = parse_cgroup_file(&contents).unwrap();
        assert_eq!(version, CgroupFileVersion::V2);
        assert!(path.starts_with("/system.slice/docker-"));
    }

    #[test]
    fn parses_a_cgroup_v1_multi_line_file() {
        let id = "b".repeat(64);
        let contents = format!(
            "11:memory:/docker/{id}\n5:cpu,cpuacct:/docker/{id}\n"
        );
        let (path, version) = parse_cgroup_file(&contents).unwrap();
        assert_eq!(version, CgroupFileVersion::V1);
        assert!(path.starts_with("/docker/"));
    }

    #[test]
    fn empty_or_garbage_content_yields_none() {
        assert!(parse_cgroup_file("").is_none());
        assert!(parse_cgroup_file("not a cgroup line at all").is_none());
        assert!(parse_cgroup_file("0::\n").is_none());
    }

    fn hex64() -> String {
        "c".repeat(64)
    }

    #[test]
    fn extracts_container_id_from_docker_systemd_scope() {
        let id = hex64();
        let path = format!("/system.slice/docker-{id}.scope");
        assert_eq!(container_id_from_cgroup_path(&path), Some(id));
    }

    #[test]
    fn extracts_container_id_from_docker_cgroupfs_path() {
        let id = hex64();
        let path = format!("/docker/{id}");
        assert_eq!(container_id_from_cgroup_path(&path), Some(id));
    }

    #[test]
    fn extracts_container_id_from_containerd_systemd_scope() {
        let id = hex64();
        let path = format!("/system.slice/cri-containerd-{id}.scope");
        assert_eq!(container_id_from_cgroup_path(&path), Some(id));
    }

    #[test]
    fn extracts_container_id_from_kubepods_path() {
        let id = hex64();
        let path = format!("/kubepods.slice/kubepods-burstable.slice/pod1234/{id}");
        assert_eq!(container_id_from_cgroup_path(&path), Some(id));
    }

    #[test]
    fn non_matching_path_returns_none() {
        assert_eq!(container_id_from_cgroup_path("/user.slice/user-1000.slice"), None);
        assert_eq!(container_id_from_cgroup_path("/"), None);
        assert_eq!(container_id_from_cgroup_path(""), None);
    }

    #[test]
    fn a_bare_hex64_segment_with_no_docker_or_kubepods_context_is_not_a_container_id() {
        let path = format!("/some.slice/{}", hex64());
        assert_eq!(container_id_from_cgroup_path(&path), None);
    }
}
