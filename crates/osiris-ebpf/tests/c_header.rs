//! The C headers `bpf/process.h`, `bpf/net.h` and `bpf/fs.h` mirror the Rust record
//! ABIs in `record.rs`, `net_record.rs` and `fs_record.rs`.
//! Clang is not available to cargo, so this test checks the header text for
//! the constants and the `_Static_assert` sizes/offsets; the C compiler then
//! enforces those asserts when `tools/ebpf/build.sh` builds the object.

use std::mem::{offset_of, size_of};
use std::path::Path;

use osiris_ebpf::{
    ExecRecord, ExitRecord, FsRecord, NetRecord, AF_INET, AF_INET6, ARGS_MAX, COMM_LEN,
    DIR_INBOUND, DIR_OUTBOUND, FILENAME_MAX, FS_SCHEMA_VERSION, KIND_EXEC, KIND_EXIT,
    KIND_FS_CREATE, KIND_FS_DELETE, KIND_FS_RENAME, KIND_FS_WRITE, KIND_NET_ACCEPT, KIND_NET_CLOSE,
    KIND_NET_CONNECT, NET_SCHEMA_VERSION, PATH_CAP, PROCESS_SCHEMA_VERSION,
};

fn header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bpf/process.h");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn c_header_matches_rust_constants() {
    let h = header();
    let expected = [
        format!("#define SCHEMA_VERSION {PROCESS_SCHEMA_VERSION}"),
        format!("#define KIND_EXEC {KIND_EXEC}"),
        format!("#define KIND_EXIT {KIND_EXIT}"),
        format!("#define ARGS_MAX {ARGS_MAX}"),
        format!("#define FILENAME_MAX {FILENAME_MAX}"),
        format!("#define COMM_LEN {COMM_LEN}"),
        format!(
            "_Static_assert(sizeof(struct exec_record) == {},",
            size_of::<ExecRecord>()
        ),
        format!(
            "_Static_assert(sizeof(struct exit_record) == {},",
            size_of::<ExitRecord>()
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, comm) == {},",
            offset_of!(ExecRecord, comm)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, exe_dev) == {},",
            offset_of!(ExecRecord, exe_dev)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, exe_ino) == {},",
            offset_of!(ExecRecord, exe_ino)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, filename) == {},",
            offset_of!(ExecRecord, filename)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, args) == {},",
            offset_of!(ExecRecord, args)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exit_record, comm) == {},",
            offset_of!(ExitRecord, comm)
        ),
    ];
    for line in &expected {
        assert!(h.contains(line.as_str()), "bpf/process.h lacks `{line}`");
    }
    // Pinned values from the brief, independent of the Rust constants.
    assert!(h.contains("#define SCHEMA_VERSION 2"));
    assert!(h.contains("_Static_assert(sizeof(struct exec_record) == 4432,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, exe_dev) == 68,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, exe_ino) == 72,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, filename) == 80,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, args) == 336,"));
    assert!(h.contains("_Static_assert(sizeof(struct exit_record) == 56,"));
}

fn net_header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bpf/net.h");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn net_c_header_matches_rust_constants() {
    let h = net_header();
    let mut expected = vec![
        format!("#define SCHEMA_VERSION {NET_SCHEMA_VERSION}"),
        format!("#define KIND_NET_CONNECT {KIND_NET_CONNECT}"),
        format!("#define KIND_NET_ACCEPT {KIND_NET_ACCEPT}"),
        format!("#define KIND_NET_CLOSE {KIND_NET_CLOSE}"),
        format!("#define AF_INET {AF_INET}"),
        format!("#define AF_INET6 {AF_INET6}"),
        format!("#define DIR_OUTBOUND {DIR_OUTBOUND}"),
        format!("#define DIR_INBOUND {DIR_INBOUND}"),
        format!("#define COMM_LEN {COMM_LEN}"),
        format!(
            "_Static_assert(sizeof(struct net_record) == {},",
            size_of::<NetRecord>()
        ),
    ];
    let offsets = [
        ("pid", offset_of!(NetRecord, pid)),
        ("uid", offset_of!(NetRecord, uid)),
        ("ktime_ns", offset_of!(NetRecord, ktime_ns)),
        ("comm", offset_of!(NetRecord, comm)),
        ("family", offset_of!(NetRecord, family)),
        ("lport", offset_of!(NetRecord, lport)),
        ("rport", offset_of!(NetRecord, rport)),
        ("direction", offset_of!(NetRecord, direction)),
        ("laddr", offset_of!(NetRecord, laddr)),
        ("raddr", offset_of!(NetRecord, raddr)),
        ("exe_dev", offset_of!(NetRecord, exe_dev)),
        ("exe_ino", offset_of!(NetRecord, exe_ino)),
    ];
    for (field, off) in offsets {
        expected.push(format!(
            "_Static_assert(__builtin_offsetof(struct net_record, {field}) == {off},"
        ));
    }
    for line in &expected {
        assert!(h.contains(line.as_str()), "bpf/net.h lacks `{line}`");
    }
    // Pinned values from the brief, independent of the Rust constants.
    assert!(h.contains("#define SCHEMA_VERSION 1"));
    assert!(h.contains("#define KIND_NET_CONNECT 3"));
    assert!(h.contains("#define KIND_NET_ACCEPT 4"));
    assert!(h.contains("#define KIND_NET_CLOSE 5"));
    assert!(h.contains("_Static_assert(sizeof(struct net_record) == 96,"));
}

fn fs_header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bpf/fs.h");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn fs_c_header_matches_rust_constants() {
    let h = fs_header();
    let mut expected = vec![
        format!("#define SCHEMA_VERSION {FS_SCHEMA_VERSION}"),
        format!("#define KIND_FS_CREATE {KIND_FS_CREATE}"),
        format!("#define KIND_FS_WRITE {KIND_FS_WRITE}"),
        format!("#define KIND_FS_DELETE {KIND_FS_DELETE}"),
        format!("#define KIND_FS_RENAME {KIND_FS_RENAME}"),
        format!("#define PATH_CAP {PATH_CAP}"),
        format!("#define COMM_LEN {COMM_LEN}"),
        format!(
            "_Static_assert(sizeof(struct fs_record) == {},",
            size_of::<FsRecord>()
        ),
    ];
    let offsets = [
        ("pid", offset_of!(FsRecord, pid)),
        ("ppid", offset_of!(FsRecord, ppid)),
        ("uid", offset_of!(FsRecord, uid)),
        ("ret", offset_of!(FsRecord, ret)),
        ("ktime_ns", offset_of!(FsRecord, ktime_ns)),
        ("comm", offset_of!(FsRecord, comm)),
        ("exe_dev", offset_of!(FsRecord, exe_dev)),
        ("dev", offset_of!(FsRecord, dev)),
        ("exe_ino", offset_of!(FsRecord, exe_ino)),
        ("ino", offset_of!(FsRecord, ino)),
        ("mode", offset_of!(FsRecord, mode)),
        ("owner_uid", offset_of!(FsRecord, owner_uid)),
        ("owner_gid", offset_of!(FsRecord, owner_gid)),
        ("has_inode", offset_of!(FsRecord, has_inode)),
        ("path_truncated", offset_of!(FsRecord, path_truncated)),
        (
            "old_path_truncated",
            offset_of!(FsRecord, old_path_truncated),
        ),
        ("path_len", offset_of!(FsRecord, path_len)),
        ("old_path_len", offset_of!(FsRecord, old_path_len)),
        ("path", offset_of!(FsRecord, path)),
        ("old_path", offset_of!(FsRecord, old_path)),
    ];
    for (field, off) in offsets {
        expected.push(format!(
            "_Static_assert(__builtin_offsetof(struct fs_record, {field}) == {off},"
        ));
    }
    for line in &expected {
        assert!(h.contains(line.as_str()), "bpf/fs.h lacks `{line}`");
    }
    // Pinned values from the brief, independent of the Rust constants.
    assert!(h.contains("#define SCHEMA_VERSION 1"));
    assert!(h.contains("#define KIND_FS_CREATE 6"));
    assert!(h.contains("#define KIND_FS_WRITE 7"));
    assert!(h.contains("#define KIND_FS_DELETE 8"));
    assert!(h.contains("#define KIND_FS_RENAME 9"));
    assert!(h.contains("#define PATH_CAP 1024"));
    assert!(h.contains("_Static_assert(sizeof(struct fs_record) == 2144,"));
}
