/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Record ABI shared between bpf/fs.bpf.c and the Rust consumer
 * (crates/osiris-ebpf/src/fs_record.rs). The two MUST stay byte-identical:
 * the Rust side pins sizes/offsets in `fs_layout_is_pinned`, this header
 * pins the same values with _Static_assert below, and the Rust test
 * `fs_c_header_matches_rust_constants` checks this file's text against the
 * Rust constants. Bump SCHEMA_VERSION on any layout change.
 *
 * This object's schema is versioned independently of process.h's and net.h's.
 */
#ifndef OSIRIS_FS_H
#define OSIRIS_FS_H

#include "vmlinux_min.h"

#define SCHEMA_VERSION 1
#define KIND_FS_CREATE 6
#define KIND_FS_WRITE 7
#define KIND_FS_DELETE 8
#define KIND_FS_RENAME 9
#define PATH_CAP 1024
#define COMM_LEN 16

/* Same header as process.h's; the headers are never included together. */
struct record_header {
	__u32 schema_version;
	__u32 kind;
};

/*
 * One record per successful create, write-open, delete or rename. Paths are
 * raw bytes without a NUL; path_len / old_path_len bytes are valid. A
 * truncated path holds the tail of the real one (dentry walk, leaf upwards).
 * old_path is only used by FS_RENAME and is zero otherwise.
 */
struct fs_record {
	struct record_header hdr;   /*   0 */
	__u32 pid;                  /*   8: tgid of the acting task */
	__u32 ppid;                 /*  12 */
	__u32 uid;                  /*  16 */
	__s32 ret;                  /*  20: syscall return value (>= 0) */
	__u64 ktime_ns;             /*  24: bpf_ktime_get_ns() at emit */
	char comm[COMM_LEN];        /*  32 */
	__u32 exe_dev;              /*  48: actor exe inode's kernel dev_t, 0 = unknown */
	__u32 dev;                  /*  52: target inode's i_sb->s_dev (kernel dev_t) */
	__u64 exe_ino;              /*  56: actor exe inode's i_ino, 0 = unknown */
	__u64 ino;                  /*  64: target inode's i_ino */
	__u32 mode;                 /*  72: i_mode */
	__u32 owner_uid;            /*  76 */
	__u32 owner_gid;            /*  80 */
	__u8 has_inode;             /*  84: dev/ino/mode/owner_* are valid */
	__u8 path_truncated;        /*  85 */
	__u8 old_path_truncated;    /*  86 */
	__u8 _pad;                  /*  87 */
	__u16 path_len;             /*  88 */
	__u16 old_path_len;         /*  90 */
	__u32 _pad2;                /*  92 */
	__u8 path[PATH_CAP];        /*  96 */
	__u8 old_path[PATH_CAP];    /* 1120; record ends at 2144 */
};

_Static_assert(sizeof(struct record_header) == 8, "record_header size");
_Static_assert(sizeof(struct fs_record) == 2144, "fs_record size");
_Static_assert(__builtin_offsetof(struct fs_record, pid) == 8, "fs pid");
_Static_assert(__builtin_offsetof(struct fs_record, ppid) == 12, "fs ppid");
_Static_assert(__builtin_offsetof(struct fs_record, uid) == 16, "fs uid");
_Static_assert(__builtin_offsetof(struct fs_record, ret) == 20, "fs ret");
_Static_assert(__builtin_offsetof(struct fs_record, ktime_ns) == 24, "fs ktime_ns");
_Static_assert(__builtin_offsetof(struct fs_record, comm) == 32, "fs comm");
_Static_assert(__builtin_offsetof(struct fs_record, exe_dev) == 48, "fs exe_dev");
_Static_assert(__builtin_offsetof(struct fs_record, dev) == 52, "fs dev");
_Static_assert(__builtin_offsetof(struct fs_record, exe_ino) == 56, "fs exe_ino");
_Static_assert(__builtin_offsetof(struct fs_record, ino) == 64, "fs ino");
_Static_assert(__builtin_offsetof(struct fs_record, mode) == 72, "fs mode");
_Static_assert(__builtin_offsetof(struct fs_record, owner_uid) == 76, "fs owner_uid");
_Static_assert(__builtin_offsetof(struct fs_record, owner_gid) == 80, "fs owner_gid");
_Static_assert(__builtin_offsetof(struct fs_record, has_inode) == 84, "fs has_inode");
_Static_assert(__builtin_offsetof(struct fs_record, path_truncated) == 85, "fs path_truncated");
_Static_assert(__builtin_offsetof(struct fs_record, old_path_truncated) == 86, "fs old_path_truncated");
_Static_assert(__builtin_offsetof(struct fs_record, path_len) == 88, "fs path_len");
_Static_assert(__builtin_offsetof(struct fs_record, old_path_len) == 90, "fs old_path_len");
_Static_assert(__builtin_offsetof(struct fs_record, path) == 96, "fs path");
_Static_assert(__builtin_offsetof(struct fs_record, old_path) == 1120, "fs old_path");

#endif /* OSIRIS_FS_H */
