//! eBPF fs record → raw event conversion (OS-neutral, so tested everywhere).
//!
//! The kernel side (`osiris-ebpf`'s `fs` program) emits one record per
//! successful create, write-open, delete or rename; each is converted on its
//! own. `ktime_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC); `timestamp_ns`
//! is it plus a realtime − monotonic offset the sensor resamples for every
//! record, exactly as the process and net backends do.

use std::path::Path;

use osiris_ebpf::{FsEvent, FsKind};

use crate::exe_index::ExeIndex;
use osiris_schema::encode_device_id;
use osiris_sensor_api::{FileEventRaw, FileOperation, RawEventSource};

/// `ktime_ns` (CLOCK_MONOTONIC) → wall-clock ns, clamped into `u64`.
fn wall_clock_ns(ktime_ns: u64, boot_wall_offset_ns: i128) -> u64 {
    let wall = i128::from(ktime_ns) + boot_wall_offset_ns;
    wall.clamp(0, i128::from(u64::MAX)) as u64
}

/// A record path as text: lossy UTF-8, with the `…/` marker in front of a
/// truncated one (the record holds the tail of the real path, so it must
/// never read as an absolute path — Global Constraint #11).
fn render_path(bytes: &[u8], truncated: bool) -> String {
    let text = String::from_utf8_lossy(bytes);
    if truncated {
        format!("\u{2026}/{text}")
    } else {
        text.into_owned()
    }
}

/// [`fs_to_raw_indexed`] with an empty identity index: `exe_path` comes
/// from `/proc/<pid>/exe` only, else `""`.
pub fn fs_to_raw(e: &FsEvent, boot_wall_offset_ns: i128, proc_root: &Path) -> FileEventRaw {
    fs_to_raw_indexed(e, boot_wall_offset_ns, proc_root, &mut ExeIndex::empty())
}

/// One decoded fs record as the existing `FileEventRaw`, converted without
/// reference to any other record. `exe_path` is the `<proc_root>/<pid>/exe`
/// link when `resolve_exe` can tie it to the record; when the process is
/// already gone, the path `exe_index` holds for the record's kernel exe
/// identity; else `""`. The record's `dev` is a kernel `dev_t`
/// (`MAJOR << 20 | MINOR`); `device_id` is `encode_device_id(major, minor)`,
/// matching the audit backend.
pub fn fs_to_raw_indexed(
    e: &FsEvent,
    boot_wall_offset_ns: i128,
    proc_root: &Path,
    exe_index: &mut ExeIndex,
) -> FileEventRaw {
    let (operation, previous_path) = match e.kind {
        FsKind::Create => (FileOperation::Create, None),
        FsKind::Write => (FileOperation::Write, None),
        FsKind::Delete => (FileOperation::Delete, None),
        FsKind::Rename => (
            FileOperation::Rename,
            Some(render_path(
                e.old_path.as_deref().unwrap_or_default(),
                e.old_path_truncated,
            )),
        ),
    };
    FileEventRaw {
        operation,
        path: render_path(&e.path, e.path_truncated),
        previous_path,
        inode: e.inode.map(|i| i.ino),
        device_id: e
            .inode
            .map(|i| encode_device_id(i.dev >> 20, i.dev & 0xf_ffff)),
        mode: e.inode.map(|i| i.mode),
        owner_uid: e.inode.map(|i| i.owner_uid),
        owner_gid: e.inode.map(|i| i.owner_gid),
        pid: e.pid,
        ppid: e.ppid,
        uid: e.uid,
        exe_path: exe_index.exe_path(e, proc_root),
        comm: e.comm.clone(),
        timestamp_ns: wall_clock_ns(e.ktime_ns, boot_wall_offset_ns),
        audit_serial: None,
        source: RawEventSource::Ebpf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_ebpf::FsInode;

    fn event(kind: FsKind) -> FsEvent {
        FsEvent {
            kind,
            pid: 4242,
            ppid: 1,
            uid: 1000,
            ret: 3,
            ktime_ns: 5_000,
            comm: "touch".to_string(),
            exe: None,
            inode: Some(FsInode {
                dev: (8 << 20) | 1,
                ino: 77,
                mode: 0o100644,
                owner_uid: 33,
                owner_gid: 34,
            }),
            path: b"/var/www/a.php".to_vec(),
            path_truncated: false,
            old_path: (kind == FsKind::Rename).then(|| b"/var/www/old.php".to_vec()),
            old_path_truncated: false,
        }
    }

    #[test]
    fn fs_to_raw_maps_kinds() {
        let root = tempfile::tempdir().unwrap();
        let cases = [
            (FsKind::Create, FileOperation::Create),
            (FsKind::Write, FileOperation::Write),
            (FsKind::Delete, FileOperation::Delete),
            (FsKind::Rename, FileOperation::Rename),
        ];
        for (kind, op) in cases {
            let raw = fs_to_raw(&event(kind), 1_000, root.path());
            assert_eq!(raw.operation, op, "{kind:?}");
            assert_eq!(raw.pid, 4242);
            assert_eq!(raw.ppid, 1);
            assert_eq!(raw.uid, 1000);
            assert_eq!(raw.comm, "touch");
            assert_eq!(raw.exe_path, "");
            assert_eq!(raw.source, RawEventSource::Ebpf);
            assert_eq!(raw.audit_serial, None);
            assert_eq!(raw.timestamp_ns, 6_000);
            assert_eq!(raw.path, "/var/www/a.php");
            assert_eq!(raw.inode, Some(77));
            assert_eq!(raw.device_id, Some(encode_device_id(8, 1)));
            assert_eq!(raw.mode, Some(0o100644));
            assert_eq!(raw.owner_uid, Some(33));
            assert_eq!(raw.owner_gid, Some(34));
            if kind == FsKind::Rename {
                assert_eq!(raw.previous_path.as_deref(), Some("/var/www/old.php"));
            } else {
                assert_eq!(raw.previous_path, None);
            }
        }
    }

    #[test]
    fn fs_to_raw_without_inode_has_no_identity() {
        let root = tempfile::tempdir().unwrap();
        let mut e = event(FsKind::Create);
        e.inode = None;
        let raw = fs_to_raw(&e, 0, root.path());
        assert_eq!(
            (
                raw.inode,
                raw.device_id,
                raw.mode,
                raw.owner_uid,
                raw.owner_gid
            ),
            (None, None, None, None, None)
        );
    }

    #[test]
    fn fs_to_raw_clamps_the_timestamp_at_zero() {
        let root = tempfile::tempdir().unwrap();
        let raw = fs_to_raw(&event(FsKind::Write), -10_000, root.path());
        assert_eq!(raw.timestamp_ns, 0);
    }

    #[test]
    fn fs_to_raw_truncation_and_lossy_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut e = event(FsKind::Create);
        e.path = b"a/b".to_vec();
        e.path_truncated = true;
        let raw = fs_to_raw(&e, 0, root.path());
        assert_eq!(raw.path, "\u{2026}/a/b");
        assert!(
            !raw.path.starts_with('/'),
            "a truncated path is never absolute"
        );

        let mut e = event(FsKind::Create);
        e.path = b"/x/\xff".to_vec();
        assert_eq!(fs_to_raw(&e, 0, root.path()).path, "/x/\u{FFFD}");

        let mut e = event(FsKind::Rename);
        e.old_path = Some(Vec::new());
        assert_eq!(
            fs_to_raw(&e, 0, root.path()).previous_path.as_deref(),
            Some("")
        );

        let mut e = event(FsKind::Rename);
        e.old_path = Some(b"c/d".to_vec());
        e.old_path_truncated = true;
        assert_eq!(
            fs_to_raw(&e, 0, root.path()).previous_path.as_deref(),
            Some("\u{2026}/c/d")
        );
    }
}
