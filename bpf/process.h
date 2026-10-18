/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Record ABI shared between bpf/process.bpf.c and the Rust consumer
 * (crates/osiris-ebpf/src/record.rs). The two MUST stay byte-identical:
 * the Rust side pins sizes/offsets in `layout_is_pinned`, this header pins
 * the same values with _Static_assert below, and the Rust test
 * `c_header_matches_rust_constants` checks this file's text against the
 * Rust constants. Bump SCHEMA_VERSION on any layout change.
 */
#ifndef OSIRIS_PROCESS_H
#define OSIRIS_PROCESS_H

#include "vmlinux_min.h"

#define SCHEMA_VERSION 1
#define KIND_EXEC 1
#define KIND_EXIT 2
#define ARGS_MAX 4096
#define FILENAME_MAX 256
#define COMM_LEN 16

struct record_header {
	__u32 schema_version;
	__u32 kind;
};

struct exec_record {
	struct record_header hdr;   /*   0 */
	__u32 pid;                  /*   8: tgid */
	__u32 ppid;                 /*  12: real_parent->tgid */
	__u32 uid;                  /*  16 */
	__u32 gid;                  /*  20 */
	__u64 ktime_ns;             /*  24: bpf_ktime_get_ns() */
	__u64 start_boottime_ns;    /*  32: task->start_boottime */
	char comm[COMM_LEN];        /*  40 */
	__u32 filename_len;         /*  56: bytes before the NUL */
	__u32 args_len;             /*  60: valid bytes in args */
	__u8 args_truncated;        /*  64 */
	__u8 _pad[7];               /*  65 */
	char filename[FILENAME_MAX]; /* 72 */
	char args[ARGS_MAX];        /* 328: NUL-separated argv */
};

struct exit_record {
	struct record_header hdr;   /*   0 */
	__u32 pid;                  /*   8: tgid */
	__u32 ppid;                 /*  12 */
	__u32 uid;                  /*  16 */
	__u32 exit_status;          /*  20: raw wait status (task->exit_code) */
	__u64 ktime_ns;             /*  24 */
	__u64 start_boottime_ns;    /*  32 */
	char comm[COMM_LEN];        /*  40 */
};

_Static_assert(sizeof(struct record_header) == 8, "record_header size");
_Static_assert(sizeof(struct exec_record) == 4424, "exec_record size");
_Static_assert(sizeof(struct exit_record) == 56, "exit_record size");
_Static_assert(__builtin_offsetof(struct exec_record, ktime_ns) == 24, "exec ktime_ns");
_Static_assert(__builtin_offsetof(struct exec_record, comm) == 40, "exec comm");
_Static_assert(__builtin_offsetof(struct exec_record, filename_len) == 56, "exec filename_len");
_Static_assert(__builtin_offsetof(struct exec_record, args_truncated) == 64, "exec args_truncated");
_Static_assert(__builtin_offsetof(struct exec_record, filename) == 72, "exec filename");
_Static_assert(__builtin_offsetof(struct exec_record, args) == 328, "exec args");
_Static_assert(__builtin_offsetof(struct exit_record, exit_status) == 20, "exit exit_status");
_Static_assert(__builtin_offsetof(struct exit_record, comm) == 40, "exit comm");

#endif /* OSIRIS_PROCESS_H */
