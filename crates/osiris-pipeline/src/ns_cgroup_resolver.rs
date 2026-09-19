use std::collections::HashMap;
use std::path::{Path, PathBuf};

use osiris_fileutil::{container_id_from_cgroup_path, parse_cgroup_file, CgroupFileVersion};
use osiris_schema::{CgroupRef, CgroupVersion, ContainerRef, NamespaceRef};

/// Resolves per-process namespace/cgroup/container context by reading
/// `{proc_root}/{pid}/cgroup` and `{proc_root}/{pid}/ns/*`, the same
/// "no dedicated sensor, resolution logic feeding Enrich" mechanism
/// ARCHITECTURE.md §4.3's Namespace/Cgroup catalog rows describe (Phase 5
/// plan Global Constraint #2). Caches by pid with no eviction (plan Global
/// Constraint #8 — same MVP posture `ProcessResolver`/`SessionResolver`
/// already have).
pub struct NsCgroupResolver {
    proc_root: PathBuf,
    cache: HashMap<u32, Option<(NamespaceRef, CgroupRef, Option<ContainerRef>)>>,
}

type NsSetter = fn(&mut NamespaceRef, u64);

const NS_KINDS: [(&str, NsSetter); 7] = [
    ("pid", |n, v| n.pid_ns = v),
    ("net", |n, v| n.net_ns = v),
    ("mnt", |n, v| n.mnt_ns = v),
    ("user", |n, v| n.user_ns = v),
    ("ipc", |n, v| n.ipc_ns = v),
    ("uts", |n, v| n.uts_ns = v),
    ("cgroup", |n, v| n.cgroup_ns = v),
];

impl NsCgroupResolver {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cache: HashMap::new(),
        }
    }

    /// Resolves (and caches) `pid`'s namespace/cgroup/container context.
    /// `None` when `{proc_root}/{pid}/cgroup` doesn't exist or doesn't
    /// parse — the process already exited, or `proc_root` doesn't model
    /// this pid — never a fabricated context. A `Some` cgroup with no
    /// resolvable container is entirely normal (most processes' cgroups
    /// are not container cgroups) and is not itself a `None` case.
    pub fn resolve(&mut self, pid: u32) -> Option<(NamespaceRef, CgroupRef, Option<ContainerRef>)> {
        if let Some(cached) = self.cache.get(&pid) {
            return cached.clone();
        }
        let resolved = self.resolve_uncached(pid);
        self.cache.insert(pid, resolved.clone());
        resolved
    }

    fn resolve_uncached(
        &self,
        pid: u32,
    ) -> Option<(NamespaceRef, CgroupRef, Option<ContainerRef>)> {
        let pid_dir = self.proc_root.join(pid.to_string());
        let cgroup_contents = std::fs::read_to_string(pid_dir.join("cgroup")).ok()?;
        let (cgroup_path, file_version) = parse_cgroup_file(&cgroup_contents)?;
        let version = match file_version {
            CgroupFileVersion::V1 => CgroupVersion::V1,
            CgroupFileVersion::V2 => CgroupVersion::V2,
        };
        let cgroup = CgroupRef {
            cgroup_path: cgroup_path.clone(),
            cgroup_id: 0,
            version,
        };

        let namespace = read_namespaces(&pid_dir.join("ns"));

        let container =
            container_id_from_cgroup_path(&cgroup_path).map(|container_id| ContainerRef {
                container_id,
                image: String::new(),
                runtime: "cgroup".to_string(),
                pod_ref: None,
            });

        Some((namespace, cgroup, container))
    }
}

/// Reads every `{ns_dir}/{kind}` entry it can, defaulting an unreadable
/// entry's field to `0` — the only non-fabricating choice available since
/// `NamespaceRef`'s fields are frozen (Phase 0) as plain `u64`, not
/// `Option<u64>`.
fn read_namespaces(ns_dir: &Path) -> NamespaceRef {
    let mut namespace = NamespaceRef {
        pid_ns: 0,
        net_ns: 0,
        mnt_ns: 0,
        user_ns: 0,
        ipc_ns: 0,
        uts_ns: 0,
        cgroup_ns: 0,
    };
    for (kind, setter) in NS_KINDS {
        let entry = ns_dir.join(kind);
        // Real `/proc/<pid>/ns/*` entries are symlinks whose target text is
        // `<kind>:[<inode>]`. `read_link` covers that real-Linux shape;
        // falling back to reading the entry as a plain file lets tests
        // model the same content without needing OS-level symlink
        // privileges (unavailable in this repo's Windows dev sandbox).
        let target = std::fs::read_link(&entry)
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .or_else(|| std::fs::read_to_string(&entry).ok());
        if let Some(target) = target {
            if let Some(inode) = parse_ns_target(target.trim()) {
                setter(&mut namespace, inode);
            }
        }
    }
    namespace
}

/// Pure parser for one `/proc/<pid>/ns/*` symlink target, e.g.
/// `"net:[4026531993]"` -> `Some(4026531993)`.
fn parse_ns_target(text: &str) -> Option<u64> {
    let start = text.find("[")?;
    let end = text.find("]")?;
    if end <= start + 1 {
        return None;
    }
    text[start + 1..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cgroup(proc_root: &Path, pid: u32, contents: &str) {
        let dir = proc_root.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup"), contents).unwrap();
    }

    #[test]
    fn parse_ns_target_extracts_the_inode() {
        assert_eq!(parse_ns_target("net:[4026531993]"), Some(4026531993));
        assert_eq!(parse_ns_target("garbage"), None);
        assert_eq!(parse_ns_target("net:[]"), None);
    }

    #[test]
    fn resolves_a_docker_cgroup_and_derives_container_context() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "d".repeat(64);
        write_cgroup(
            tmp.path(),
            1234,
            &format!("0::/system.slice/docker-{id}.scope\n"),
        );
        let mut resolver = NsCgroupResolver::new(tmp.path());
        let (_ns, cgroup, container) = resolver.resolve(1234).expect("must resolve");
        assert_eq!(cgroup.version, CgroupVersion::V2);
        assert!(cgroup.cgroup_path.contains(&id));
        let container = container.expect("container must resolve from the docker cgroup path");
        assert_eq!(container.container_id, id);
        assert_eq!(container.runtime, "cgroup");
    }

    #[test]
    fn resolves_a_non_container_cgroup_with_no_container_context() {
        let tmp = tempfile::tempdir().unwrap();
        write_cgroup(tmp.path(), 1, "0::/init.scope\n");
        let mut resolver = NsCgroupResolver::new(tmp.path());
        let (_ns, cgroup, container) = resolver.resolve(1).expect("must resolve");
        assert_eq!(cgroup.cgroup_path, "/init.scope");
        assert!(container.is_none());
    }

    #[test]
    fn returns_none_for_a_pid_with_no_cgroup_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut resolver = NsCgroupResolver::new(tmp.path());
        assert!(resolver.resolve(9999).is_none());
    }

    /// Global Constraint #8: a resolved value is cached, not re-read on
    /// every call — proven by mutating the on-disk file between two
    /// `resolve()` calls for the same pid and asserting the second call
    /// still returns the first call's value.
    #[test]
    fn resolve_caches_and_does_not_re_read_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let id_a = "a".repeat(64);
        write_cgroup(tmp.path(), 42, &format!("0::/docker/{id_a}\n"));
        let mut resolver = NsCgroupResolver::new(tmp.path());
        let (_, first_cgroup, first_container) = resolver.resolve(42).unwrap();
        assert_eq!(first_container.unwrap().container_id, id_a);

        let id_b = "b".repeat(64);
        write_cgroup(tmp.path(), 42, &format!("0::/docker/{id_b}\n"));
        let (_, second_cgroup, second_container) = resolver.resolve(42).unwrap();
        assert_eq!(second_cgroup.cgroup_path, first_cgroup.cgroup_path);
        assert_eq!(
            second_container.unwrap().container_id,
            id_a,
            "must still be the cached value, not the mutated file's"
        );
    }

    /// Real Linux: `/proc/<pid>/ns/net` is a symlink whose target text is
    /// `net:[<inode>]`. Gated to unix only (symlink creation needs
    /// elevated privileges on Windows) — this proves the real-Linux shape
    /// end-to-end without blocking this repo's Windows dev build.
    #[cfg(unix)]
    #[test]
    fn reads_real_namespace_symlinks_on_unix() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let id = "e".repeat(64);
        write_cgroup(tmp.path(), 555, &format!("0::/docker/{id}\n"));
        let ns_dir = tmp.path().join("555").join("ns");
        std::fs::create_dir_all(&ns_dir).unwrap();
        symlink("net:[4026531993]", ns_dir.join("net")).unwrap();
        let mut resolver = NsCgroupResolver::new(tmp.path());
        let (namespace, _, _) = resolver.resolve(555).unwrap();
        assert_eq!(namespace.net_ns, 4026531993);
    }
}
