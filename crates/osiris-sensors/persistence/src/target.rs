use std::path::PathBuf;

use osiris_sensor_api::PersistenceCheckpointKind;
use serde::Deserialize;

/// One config-declared thing to watch (plan Global Constraint #4): a path
/// (file or directory) and the checkpoint kind it holds. Explicit,
/// never inferred from the path string itself — an operator who points
/// `kind: cron` at the wrong directory gets exactly what they configured.
#[derive(Debug, Clone, Deserialize)]
pub struct PersistenceWatchTarget {
    pub path: String,
    pub kind: PersistenceWatchKind,
}

/// The declared kind of a watch target. `SystemdUnitDir` is the one kind
/// this crate further splits *within* itself, by file extension, into
/// `PersistenceCheckpointKind::SystemdUnit`/`SystemdTimer` — every other
/// kind maps 1:1 onto one `PersistenceCheckpointKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceWatchKind {
    SystemdUnitDir,
    Cron,
    ShellProfile,
    LdPreload,
    Sudoers,
}

/// Classifies one discovered file against the watch target that found it.
/// For `SystemdUnitDir`, only `.service` and `.timer` files are recognized
/// — anything else in that directory (`.socket`, `.mount`, `.path`, etc.)
/// returns `None` and the caller skips it silently (plan Global Constraint
/// #4: a documented, deliberate drop, not a guess).
pub fn checkpoint_kind_for(target_kind: PersistenceWatchKind, path: &std::path::Path) -> Option<PersistenceCheckpointKind> {
    match target_kind {
        PersistenceWatchKind::SystemdUnitDir => match path.extension().and_then(|e| e.to_str()) {
            Some("service") => Some(PersistenceCheckpointKind::SystemdUnit),
            Some("timer") => Some(PersistenceCheckpointKind::SystemdTimer),
            _ => None,
        },
        PersistenceWatchKind::Cron => Some(PersistenceCheckpointKind::Cron),
        PersistenceWatchKind::ShellProfile => Some(PersistenceCheckpointKind::ShellProfile),
        PersistenceWatchKind::LdPreload => Some(PersistenceCheckpointKind::LdPreload),
        PersistenceWatchKind::Sudoers => Some(PersistenceCheckpointKind::Sudoers),
    }
}

/// Lists the candidate files a target actually covers right now: every
/// immediate entry (non-recursive — plan-scoped minimalism, matching this
/// codebase's "MVP scope, not the eventual design" style elsewhere) if
/// `target.path` is a directory, or the single path itself if it's a file
/// (`/etc/crontab`, `/etc/ld.so.preload` are watched as one file each, not
/// a directory). A target whose path does not exist yet yields no
/// candidates — not an error, since a not-yet-created persistence
/// checkpoint directory is a completely ordinary state, not a fault.
pub fn candidate_paths(target: &PersistenceWatchTarget) -> Vec<PathBuf> {
    let path = PathBuf::from(&target.path);
    if path.is_dir() {
        std::fs::read_dir(&path)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| p.is_file())
            .collect()
    } else if path.is_file() {
        vec![path]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_file_in_a_unit_dir_classifies_as_systemd_unit() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.service")
            ),
            Some(PersistenceCheckpointKind::SystemdUnit)
        );
    }

    #[test]
    fn a_timer_file_in_a_unit_dir_classifies_as_systemd_timer() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.timer")
            ),
            Some(PersistenceCheckpointKind::SystemdTimer)
        );
    }

    #[test]
    fn a_socket_file_in_a_unit_dir_is_silently_skipped() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::SystemdUnitDir,
                std::path::Path::new("/etc/systemd/system/backdoor.socket")
            ),
            None
        );
    }

    #[test]
    fn a_cron_target_classifies_everything_as_cron_regardless_of_extension() {
        assert_eq!(
            checkpoint_kind_for(
                PersistenceWatchKind::Cron,
                std::path::Path::new("/etc/cron.d/anything.txt")
            ),
            Some(PersistenceCheckpointKind::Cron)
        );
    }

    #[test]
    fn candidate_paths_lists_immediate_files_in_a_directory_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.service"), "x").unwrap();
        std::fs::write(dir.path().join("b.timer"), "y").unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        let target = PersistenceWatchTarget {
            path: dir.path().to_string_lossy().to_string(),
            kind: PersistenceWatchKind::SystemdUnitDir,
        };
        let mut found: Vec<_> = candidate_paths(&target)
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        found.sort();
        assert_eq!(found, vec!["a.service".to_string(), "b.timer".to_string()]);
    }

    #[test]
    fn candidate_paths_treats_a_single_file_target_as_one_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ld.so.preload");
        std::fs::write(&file, "x").unwrap();
        let target = PersistenceWatchTarget {
            path: file.to_string_lossy().to_string(),
            kind: PersistenceWatchKind::LdPreload,
        };
        assert_eq!(candidate_paths(&target).len(), 1);
    }

    #[test]
    fn candidate_paths_is_empty_for_a_target_that_does_not_exist_yet() {
        let target = PersistenceWatchTarget {
            path: "/does/not/exist".to_string(),
            kind: PersistenceWatchKind::Cron,
        };
        assert!(candidate_paths(&target).is_empty());
    }
}
