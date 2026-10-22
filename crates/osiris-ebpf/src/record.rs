//! Record ABI shared with the C BPF program (`bpf/`), plus decoding.
//!
//! The structs use natural C alignment; their layout is pinned by the
//! `layout_is_pinned` test. Records arrive from the kernel ring buffer and are
//! treated as untrusted: decoding is length-checked, lengths are clamped and
//! it never panics.

use std::mem::size_of;

use crate::exe::{dev_to_user, ExeIdentity};

pub const PROCESS_SCHEMA_VERSION: u32 = 2;
pub const KIND_EXEC: u32 = 1;
pub const KIND_EXIT: u32 = 2;
pub const ARGS_MAX: usize = 4096;
pub const FILENAME_MAX: usize = 256;
pub const COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecordHeader {
    pub schema_version: u32,
    pub kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecRecord {
    pub hdr: RecordHeader,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ktime_ns: u64,
    pub start_boottime_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub filename_len: u32,
    pub args_len: u32,
    pub args_truncated: u8,
    pub _pad: [u8; 3],
    /// Kernel-internal `dev_t` of `mm->exe_file`'s superblock (0 = unknown).
    pub exe_dev: u32,
    /// `mm->exe_file`'s inode number (0 = unknown).
    pub exe_ino: u64,
    pub filename: [u8; FILENAME_MAX],
    pub args: [u8; ARGS_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitRecord {
    pub hdr: RecordHeader,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exit_status: u32,
    pub ktime_ns: u64,
    pub start_boottime_ns: u64,
    pub comm: [u8; COMM_LEN],
}

/// Decoded exec record (owned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub ktime_ns: u64,
    pub start_boottime_ns: u64,
    pub comm: String,
    pub filename: String,
    /// Raw argv bytes (NUL-separated), clamped to [`ARGS_MAX`].
    pub args: Vec<u8>,
    pub args_truncated: bool,
    /// The exec'd image's identity as the kernel saw it; `None` when the
    /// record carries inode 0 (no `mm`/`exe_file`, or the read failed).
    pub exe: Option<ExeIdentity>,
}

/// Decoded exit record (owned). `exit_status` is the raw wait status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exit_status: u32,
    pub ktime_ns: u64,
    pub start_boottime_ns: u64,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Exec(ExecEvent),
    Exit(ExitEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("record shorter than header ({0} bytes)")]
    ShorterThanHeader(usize),
    #[error("unsupported schema version {0}")]
    UnsupportedVersion(u32),
    #[error("unknown record kind {0}")]
    UnknownKind(u32),
    #[error("record truncated for kind {kind}: {got} < {need} bytes")]
    Truncated { kind: u32, got: usize, need: usize },
}

/// Decode one ring-buffer record. Never panics on arbitrary input.
pub fn decode(bytes: &[u8]) -> Result<Record, DecodeError> {
    if bytes.len() < size_of::<RecordHeader>() {
        return Err(DecodeError::ShorterThanHeader(bytes.len()));
    }
    let hdr: RecordHeader = read(bytes);
    if hdr.schema_version != PROCESS_SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedVersion(hdr.schema_version));
    }
    let need = match hdr.kind {
        KIND_EXEC => size_of::<ExecRecord>(),
        KIND_EXIT => size_of::<ExitRecord>(),
        k => return Err(DecodeError::UnknownKind(k)),
    };
    if bytes.len() < need {
        return Err(DecodeError::Truncated {
            kind: hdr.kind,
            got: bytes.len(),
            need,
        });
    }
    if hdr.kind == KIND_EXEC {
        let r: ExecRecord = read(bytes);
        let args_len = (r.args_len as usize).min(ARGS_MAX);
        Ok(Record::Exec(ExecEvent {
            pid: r.pid,
            ppid: r.ppid,
            uid: r.uid,
            ktime_ns: r.ktime_ns,
            start_boottime_ns: r.start_boottime_ns,
            comm: c_string(&r.comm, COMM_LEN),
            filename: c_string(&r.filename, (r.filename_len as usize).min(FILENAME_MAX)),
            args: r.args[..args_len].to_vec(),
            args_truncated: r.args_truncated != 0,
            exe: (r.exe_ino != 0).then(|| ExeIdentity {
                dev: dev_to_user(r.exe_dev),
                ino: r.exe_ino,
            }),
        }))
    } else {
        let r: ExitRecord = read(bytes);
        Ok(Record::Exit(ExitEvent {
            pid: r.pid,
            ppid: r.ppid,
            uid: r.uid,
            exit_status: r.exit_status,
            ktime_ns: r.ktime_ns,
            start_boottime_ns: r.start_boottime_ns,
            comm: c_string(&r.comm, COMM_LEN),
        }))
    }
}

/// Read a `T` from the front of `bytes`; callers check the length first.
/// `T` must be valid for any bit pattern (plain integers and byte arrays).
fn read<T: Copy>(bytes: &[u8]) -> T {
    assert!(bytes.len() >= size_of::<T>());
    // SAFETY: length asserted above; read_unaligned needs no alignment.
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

/// NUL-terminated string from at most `len` bytes of `bytes`, lossy UTF-8.
fn c_string(bytes: &[u8], len: usize) -> String {
    let b = &bytes[..len.min(bytes.len())];
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Decode a Linux wait status into `(exit_code, signal)`.
pub fn decode_wait_status(status: u32) -> (Option<i32>, Option<u32>) {
    let sig = status & 0x7f;
    if sig == 0 {
        (Some(((status >> 8) & 0xff) as i32), None)
    } else {
        (None, Some(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, zeroed};

    fn as_bytes<T>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain-old-data struct.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    fn exec() -> ExecRecord {
        // SAFETY: all-zero is a valid ExecRecord.
        let mut r: ExecRecord = unsafe { zeroed() };
        r.hdr = RecordHeader {
            schema_version: PROCESS_SCHEMA_VERSION,
            kind: KIND_EXEC,
        };
        r.pid = 10;
        r.ppid = 1;
        r.uid = 1000;
        r.ktime_ns = 5;
        r.start_boottime_ns = 7;
        r.comm[..3].copy_from_slice(b"cat");
        r.filename[..8].copy_from_slice(b"/bin/cat");
        r.filename_len = 8;
        r.args[..9].copy_from_slice(b"cat\0/etc\0");
        r.args_len = 9;
        r.args_truncated = 1;
        r
    }

    fn exit() -> ExitRecord {
        // SAFETY: all-zero is a valid ExitRecord.
        let mut r: ExitRecord = unsafe { zeroed() };
        r.hdr = RecordHeader {
            schema_version: PROCESS_SCHEMA_VERSION,
            kind: KIND_EXIT,
        };
        r.pid = 10;
        r.ppid = 1;
        r.uid = 1000;
        r.exit_status = 7 << 8;
        r.ktime_ns = 9;
        r.start_boottime_ns = 7;
        r.comm[..3].copy_from_slice(b"cat");
        r
    }

    #[test]
    fn layout_is_pinned() {
        assert_eq!(PROCESS_SCHEMA_VERSION, 2);
        assert_eq!(size_of::<ExecRecord>(), 4432);
        assert_eq!(size_of::<ExitRecord>(), 56);
        assert_eq!(offset_of!(ExecRecord, pid), 8);
        assert_eq!(offset_of!(ExecRecord, ppid), 12);
        assert_eq!(offset_of!(ExecRecord, uid), 16);
        assert_eq!(offset_of!(ExecRecord, gid), 20);
        assert_eq!(offset_of!(ExecRecord, ktime_ns), 24);
        assert_eq!(offset_of!(ExecRecord, start_boottime_ns), 32);
        assert_eq!(offset_of!(ExecRecord, comm), 40);
        assert_eq!(offset_of!(ExecRecord, filename_len), 56);
        assert_eq!(offset_of!(ExecRecord, args_len), 60);
        assert_eq!(offset_of!(ExecRecord, args_truncated), 64);
        assert_eq!(offset_of!(ExecRecord, _pad), 65);
        assert_eq!(offset_of!(ExecRecord, exe_dev), 68);
        assert_eq!(offset_of!(ExecRecord, exe_ino), 72);
        assert_eq!(offset_of!(ExecRecord, filename), 80);
        assert_eq!(offset_of!(ExecRecord, args), 336);
        assert_eq!(offset_of!(ExitRecord, exit_status), 20);
        assert_eq!(offset_of!(ExitRecord, comm), 40);
    }

    #[test]
    fn decode_exec_v2_carries_exe_identity() {
        match decode(&as_bytes(&exec())).unwrap() {
            Record::Exec(e) => assert_eq!(e.exe, None),
            other => panic!("{other:?}"),
        }
        let mut r = exec();
        r.exe_dev = (8 << 20) | 1;
        r.exe_ino = 42;
        match decode(&as_bytes(&r)).unwrap() {
            Record::Exec(e) => assert_eq!(e.exe, Some(ExeIdentity { dev: 2049, ino: 42 })),
            other => panic!("{other:?}"),
        }
        // A zero inode means "no identity", whatever the device says.
        r.exe_ino = 0;
        match decode(&as_bytes(&r)).unwrap() {
            Record::Exec(e) => assert_eq!(e.exe, None),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn decode_rejects_v1_records() {
        let mut r = exec();
        r.hdr.schema_version = 1;
        assert_eq!(
            decode(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(1))
        );
        let mut r = exit();
        r.hdr.schema_version = 1;
        assert_eq!(
            decode(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn decode_round_trips_exec_and_exit() {
        match decode(&as_bytes(&exec())).unwrap() {
            Record::Exec(e) => {
                assert_eq!((e.pid, e.ppid, e.uid, e.ktime_ns), (10, 1, 1000, 5));
                assert_eq!(e.start_boottime_ns, 7);
                assert_eq!(e.comm, "cat");
                assert_eq!(e.filename, "/bin/cat");
                assert_eq!(e.args, b"cat\0/etc\0");
                assert!(e.args_truncated);
            }
            other => panic!("{other:?}"),
        }
        match decode(&as_bytes(&exit())).unwrap() {
            Record::Exit(e) => {
                assert_eq!((e.pid, e.exit_status, e.ktime_ns), (10, 7 << 8, 9));
                assert_eq!(e.comm, "cat");
            }
            other => panic!("{other:?}"),
        }
        // Trailing bytes beyond the struct are tolerated.
        let mut b = as_bytes(&exit());
        b.extend_from_slice(&[0; 8]);
        assert!(decode(&b).is_ok());
    }

    #[test]
    fn decode_rejects_short_and_wrong_version() {
        assert!(matches!(
            decode(&[1, 0, 0]),
            Err(DecodeError::ShorterThanHeader(3))
        ));
        let b = as_bytes(&exec());
        assert!(matches!(
            decode(&b[..100]),
            Err(DecodeError::Truncated { kind: 1, .. })
        ));
        let b = as_bytes(&exit());
        assert!(matches!(
            decode(&b[..55]),
            Err(DecodeError::Truncated { kind: 2, .. })
        ));
        let mut r = exit();
        r.hdr.schema_version = 3;
        assert_eq!(
            decode(&as_bytes(&r)),
            Err(DecodeError::UnsupportedVersion(3))
        );
        let mut r = exit();
        r.hdr.kind = 9;
        assert_eq!(decode(&as_bytes(&r)), Err(DecodeError::UnknownKind(9)));
    }

    #[test]
    fn lengths_are_clamped() {
        let mut r = exec();
        r.filename = [b'a'; FILENAME_MAX];
        r.filename_len = 9999;
        r.args = [b'x'; ARGS_MAX];
        r.args_len = u32::MAX;
        match decode(&as_bytes(&r)).unwrap() {
            Record::Exec(e) => {
                assert_eq!(e.filename.len(), FILENAME_MAX);
                assert_eq!(e.args.len(), ARGS_MAX);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wait_status_decoding() {
        assert_eq!(decode_wait_status(7 << 8), (Some(7), None));
        assert_eq!(decode_wait_status(9), (None, Some(9)));
        assert_eq!(decode_wait_status(0), (Some(0), None));
    }
}
