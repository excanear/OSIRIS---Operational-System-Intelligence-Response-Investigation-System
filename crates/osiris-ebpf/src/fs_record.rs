//! Filesystem record ABI shared with `bpf/fs.bpf.c` (`bpf/fs.h`), plus
//! decoding.
//!
//! One fixed-size record per successful create, write-open, delete or
//! rename. The layout is pinned by `fs_layout_is_pinned` and mirrored by
//! `_Static_assert`s in `bpf/fs.h`. Records arrive from the kernel ring
//! buffer and are treated as untrusted: decoding is length-checked, path
//! lengths are bounded by [`PATH_CAP`] and it never panics. It shares the
//! header, [`DecodeError`] and the read helpers with the process record
//! (`record`).

use std::mem::size_of;

use crate::exe::{dev_to_user, ExeIdentity};
use crate::record::{c_string, read, DecodeError, RecordHeader, COMM_LEN};

pub const FS_SCHEMA_VERSION: u32 = 1;
pub const KIND_FS_CREATE: u32 = 6;
pub const KIND_FS_WRITE: u32 = 7;
pub const KIND_FS_DELETE: u32 = 8;
pub const KIND_FS_RENAME: u32 = 9;
/// Capacity in bytes of each path buffer in a record.
pub const PATH_CAP: usize = 1024;

/// One filesystem event. Paths are raw bytes (no NUL), `path_len` /
/// `old_path_len` of them valid. A truncated path holds the tail of the
/// real one (the kernel walks dentries from the leaf upwards).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsRecord {
    pub hdr: RecordHeader,
    /// Tgid of the task that performed the operation.
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// The syscall's return value (always `>= 0`: only successes are emitted).
    pub ret: i32,
    /// `bpf_ktime_get_ns()` when the record was emitted.
    pub ktime_ns: u64,
    pub comm: [u8; COMM_LEN],
    /// Kernel-internal `dev_t` of the actor's `mm->exe_file` (0 = unknown).
    pub exe_dev: u32,
    /// Kernel-internal `dev_t` of the target inode's superblock.
    pub dev: u32,
    pub exe_ino: u64,
    /// Target inode number.
    pub ino: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    /// 1 when `dev`/`ino`/`mode`/`owner_*` are filled in.
    pub has_inode: u8,
    pub path_truncated: u8,
    pub old_path_truncated: u8,
    pub _pad: u8,
    pub path_len: u16,
    pub old_path_len: u16,
    pub _pad2: u32,
    pub path: [u8; PATH_CAP],
    /// Source path of a rename; unused (zero) for other kinds.
    pub old_path: [u8; PATH_CAP],
}

/// Record kind of an [`FsEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Create,
    Write,
    Delete,
    Rename,
}

/// Target inode metadata of an [`FsEvent`]. `dev` is the kernel-internal
/// `dev_t` (`MAJOR << 20 | MINOR`, as in the watch keys); convert it with
/// [`dev_to_user`] to compare with `st_dev`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsInode {
    pub dev: u32,
    pub ino: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

/// Decoded fs record (owned). Field meanings as in [`FsRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    pub kind: FsKind,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub ret: i32,
    pub ktime_ns: u64,
    pub comm: String,
    /// The actor's executable; `None` when the record carries inode 0.
    pub exe: Option<ExeIdentity>,
    /// `None` when `has_inode` is 0 or the inode number is 0.
    pub inode: Option<FsInode>,
    pub path: Vec<u8>,
    pub path_truncated: bool,
    /// `Some` only for [`FsKind::Rename`].
    pub old_path: Option<Vec<u8>>,
    pub old_path_truncated: bool,
}

/// Decode one fs ring-buffer record. Never panics on arbitrary input;
/// non-fs kinds, other schemas, short buffers and path lengths above
/// [`PATH_CAP`] are errors.
pub fn decode_fs(bytes: &[u8]) -> Result<FsEvent, DecodeError> {
    if bytes.len() < size_of::<RecordHeader>() {
        return Err(DecodeError::ShorterThanHeader(bytes.len()));
    }
    let hdr: RecordHeader = read(bytes);
    if hdr.schema_version != FS_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedVersion(hdr.schema_version));
    }
    let kind = match hdr.kind {
        KIND_FS_CREATE => FsKind::Create,
        KIND_FS_WRITE => FsKind::Write,
        KIND_FS_DELETE => FsKind::Delete,
        KIND_FS_RENAME => FsKind::Rename,
        k => return Err(DecodeError::UnknownKind(k)),
    };
    let need = size_of::<FsRecord>();
    if bytes.len() < need {
        return Err(DecodeError::Truncated {
            kind: hdr.kind,
            got: bytes.len(),
            need,
        });
    }
    let r: FsRecord = read(bytes);
    if usize::from(r.path_len) > PATH_CAP {
        return Err(DecodeError::PathTooLong {
            field: "path",
            len: r.path_len,
        });
    }
    let is_rename = kind == FsKind::Rename;
    if is_rename && usize::from(r.old_path_len) > PATH_CAP {
        return Err(DecodeError::PathTooLong {
            field: "old_path",
            len: r.old_path_len,
        });
    }
    Ok(FsEvent {
        kind,
        pid: r.pid,
        ppid: r.ppid,
        uid: r.uid,
        ret: r.ret,
        ktime_ns: r.ktime_ns,
        comm: c_string(&r.comm, COMM_LEN),
        exe: (r.exe_ino != 0).then(|| ExeIdentity {
            dev: dev_to_user(r.exe_dev),
            ino: r.exe_ino,
        }),
        inode: (r.has_inode != 0 && r.ino != 0).then_some(FsInode {
            dev: r.dev,
            ino: r.ino,
            mode: r.mode,
            owner_uid: r.owner_uid,
            owner_gid: r.owner_gid,
        }),
        path: r.path[..usize::from(r.path_len)].to_vec(),
        path_truncated: r.path_truncated != 0,
        old_path: is_rename.then(|| r.old_path[..usize::from(r.old_path_len)].to_vec()),
        old_path_truncated: is_rename && r.old_path_truncated != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{AttachKind, FS_OBJECT};
    use std::mem::{offset_of, size_of, zeroed};

    fn as_bytes<T>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain-old-data struct.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    fn base(kind: u32) -> FsRecord {
        // SAFETY: all-zero is a valid FsRecord.
        let mut r: FsRecord = unsafe { zeroed() };
        r.hdr = RecordHeader {
            schema_version: FS_SCHEMA_VERSION,
            kind,
        };
        r.pid = 4242;
        r.ppid = 1;
        r.uid = 1000;
        r.ret = 0;
        r.ktime_ns = 99;
        r.comm[..3].copy_from_slice(b"mv\0");
        r.exe_dev = (8 << 20) | 1;
        r.exe_ino = 77;
        r
    }

    fn set_path(r: &mut FsRecord, p: &[u8]) {
        r.path[..p.len()].copy_from_slice(p);
        r.path_len = p.len() as u16;
    }

    #[test]
    fn fs_layout_is_pinned() {
        assert_eq!(FS_SCHEMA_VERSION, 1);
        assert_eq!(
            (
                KIND_FS_CREATE,
                KIND_FS_WRITE,
                KIND_FS_DELETE,
                KIND_FS_RENAME
            ),
            (6, 7, 8, 9)
        );
        assert_eq!(PATH_CAP, 1024);
        assert_eq!(size_of::<FsRecord>(), 2144);
        assert_eq!(offset_of!(FsRecord, hdr), 0);
        assert_eq!(offset_of!(FsRecord, pid), 8);
        assert_eq!(offset_of!(FsRecord, ppid), 12);
        assert_eq!(offset_of!(FsRecord, uid), 16);
        assert_eq!(offset_of!(FsRecord, ret), 20);
        assert_eq!(offset_of!(FsRecord, ktime_ns), 24);
        assert_eq!(offset_of!(FsRecord, comm), 32);
        assert_eq!(offset_of!(FsRecord, exe_dev), 48);
        assert_eq!(offset_of!(FsRecord, dev), 52);
        assert_eq!(offset_of!(FsRecord, exe_ino), 56);
        assert_eq!(offset_of!(FsRecord, ino), 64);
        assert_eq!(offset_of!(FsRecord, mode), 72);
        assert_eq!(offset_of!(FsRecord, owner_uid), 76);
        assert_eq!(offset_of!(FsRecord, owner_gid), 80);
        assert_eq!(offset_of!(FsRecord, has_inode), 84);
        assert_eq!(offset_of!(FsRecord, path_truncated), 85);
        assert_eq!(offset_of!(FsRecord, old_path_truncated), 86);
        assert_eq!(offset_of!(FsRecord, _pad), 87);
        assert_eq!(offset_of!(FsRecord, path_len), 88);
        assert_eq!(offset_of!(FsRecord, old_path_len), 90);
        assert_eq!(offset_of!(FsRecord, _pad2), 92);
        assert_eq!(offset_of!(FsRecord, path), 96);
        assert_eq!(offset_of!(FsRecord, old_path), 1120);
    }

    #[test]
    fn decode_fs_rename_and_create() {
        let mut r = base(KIND_FS_RENAME);
        set_path(&mut r, b"/tmp/new");
        r.old_path[..8].copy_from_slice(b"/tmp/old");
        r.old_path_len = 8;
        r.path_truncated = 1;
        r.has_inode = 1;
        r.dev = (8 << 20) | 1;
        r.ino = 5;
        r.mode = 0o100644;
        r.owner_uid = 7;
        r.owner_gid = 8;
        let e = decode_fs(&as_bytes(&r)).unwrap();
        assert_eq!(e.kind, FsKind::Rename);
        assert_eq!(
            (e.pid, e.ppid, e.uid, e.ret, e.ktime_ns),
            (4242, 1, 1000, 0, 99)
        );
        assert_eq!(e.comm, "mv");
        assert_eq!(e.exe, Some(ExeIdentity { dev: 2049, ino: 77 }));
        assert_eq!(e.path, b"/tmp/new");
        assert!(e.path_truncated);
        assert_eq!(e.old_path.as_deref(), Some(&b"/tmp/old"[..]));
        assert!(!e.old_path_truncated);
        assert_eq!(
            e.inode,
            Some(FsInode {
                dev: (8 << 20) | 1,
                ino: 5,
                mode: 0o100644,
                owner_uid: 7,
                owner_gid: 8
            })
        );

        let mut c = base(KIND_FS_CREATE);
        set_path(&mut c, b"/etc/x");
        c.old_path_len = 3; // ignored for non-rename kinds
        c.exe_ino = 0;
        c.ino = 9;
        c.has_inode = 0;
        let e = decode_fs(&as_bytes(&c)).unwrap();
        assert_eq!(e.kind, FsKind::Create);
        assert_eq!(e.inode, None);
        assert_eq!(e.old_path, None);
        assert_eq!(e.exe, None);

        // A zero ino also means no inode, even with has_inode set.
        c.has_inode = 1;
        c.ino = 0;
        assert_eq!(decode_fs(&as_bytes(&c)).unwrap().inode, None);

        for (k, want) in [
            (KIND_FS_WRITE, FsKind::Write),
            (KIND_FS_DELETE, FsKind::Delete),
        ] {
            assert_eq!(decode_fs(&as_bytes(&base(k))).unwrap().kind, want);
        }
        // Rename with an empty old path keeps Some(empty).
        let e = decode_fs(&as_bytes(&base(KIND_FS_RENAME))).unwrap();
        assert_eq!(e.old_path, Some(Vec::new()));
    }

    #[test]
    fn fs_decode_rejects_bad_lengths_and_kinds() {
        let mut r = base(KIND_FS_CREATE);
        r.path_len = 1025;
        assert_eq!(
            decode_fs(&as_bytes(&r)),
            Err(DecodeError::PathTooLong {
                field: "path",
                len: 1025
            })
        );
        let mut r = base(KIND_FS_RENAME);
        r.old_path_len = 1025;
        assert_eq!(
            decode_fs(&as_bytes(&r)),
            Err(DecodeError::PathTooLong {
                field: "old_path",
                len: 1025
            })
        );
        // Exactly PATH_CAP is fine.
        let mut r = base(KIND_FS_CREATE);
        r.path = [b'a'; PATH_CAP];
        r.path_len = 1024;
        assert_eq!(decode_fs(&as_bytes(&r)).unwrap().path.len(), 1024);

        let b = as_bytes(&base(KIND_FS_CREATE));
        assert_eq!(
            decode_fs(&b[..2143]),
            Err(DecodeError::Truncated {
                kind: KIND_FS_CREATE,
                got: 2143,
                need: 2144
            })
        );
        assert_eq!(decode_fs(&b[..3]), Err(DecodeError::ShorterThanHeader(3)));

        for kind in [5, 10, 0] {
            assert_eq!(
                decode_fs(&as_bytes(&base(kind))),
                Err(DecodeError::UnknownKind(kind))
            );
        }
        let mut r = base(KIND_FS_CREATE);
        r.hdr.schema_version = 2;
        assert_eq!(
            decode_fs(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(2))
        );

        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for i in 0..10_000u32 {
            let len = (next() % 2300) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if i % 3 == 0 && len >= 8 {
                buf[..4].copy_from_slice(&FS_SCHEMA_VERSION.to_ne_bytes());
                let kind = KIND_FS_CREATE + (next() % 4) as u32;
                buf[4..8].copy_from_slice(&kind.to_ne_bytes());
            }
            let _ = decode_fs(&buf);
        }
    }

    #[test]
    fn fs_object_spec_names() {
        assert_eq!(FS_OBJECT.object_file, "fs.bpf.o");
        assert_eq!(FS_OBJECT.expected_schema, 1);
        let mut want: Vec<(String, AttachKind, bool)> = Vec::new();
        for (prog, sym, req) in [
            ("kp_path_mknod", "security_path_mknod", true),
            ("kp_path_mkdir", "security_path_mkdir", true),
            ("kp_path_unlink", "security_path_unlink", true),
            ("kp_path_rmdir", "security_path_rmdir", true),
            ("kp_path_rename", "security_path_rename", true),
            ("kp_file_open", "security_file_open", true),
            ("kp_path_truncate", "security_path_truncate", true),
            ("kp_file_truncate", "security_file_truncate", false),
        ] {
            want.push((prog.into(), AttachKind::KProbe { symbol: sym }, req));
        }
        let optional = [
            "open", "creat", "mknod", "mkdir", "unlink", "rmdir", "rename", "openat2",
        ];
        for sc in [
            "open",
            "openat",
            "openat2",
            "creat",
            "truncate",
            "ftruncate",
            "mknod",
            "mknodat",
            "mkdir",
            "mkdirat",
            "unlink",
            "unlinkat",
            "rmdir",
            "rename",
            "renameat",
            "renameat2",
        ] {
            let req = !optional.contains(&sc);
            for dir in ["enter", "exit"] {
                // Leak is fine in a test: AttachKind wants 'static strs.
                let name: &'static str = Box::leak(format!("sys_{dir}_{sc}").into_boxed_str());
                want.push((
                    format!("tp_{dir}_{sc}"),
                    AttachKind::TracePoint {
                        category: "syscalls",
                        name,
                    },
                    req,
                ));
            }
        }
        want.push((
            "tp_task_exit".into(),
            AttachKind::TracePoint {
                category: "sched",
                name: "sched_process_exit",
            },
            true,
        ));
        let got: Vec<(String, AttachKind, bool)> = FS_OBJECT
            .attach
            .iter()
            .map(|a| (a.program.to_string(), a.kind, a.required))
            .collect();
        assert_eq!(got.len(), want.len());
        for w in &want {
            assert!(got.contains(w), "missing or wrong attach point {w:?}");
        }
    }
}
