/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Record ABI shared between bpf/net.bpf.c and the Rust consumer
 * (crates/osiris-ebpf/src/net_record.rs). The two MUST stay byte-identical:
 * the Rust side pins sizes/offsets in `net_layout_is_pinned`, this header
 * pins the same values with _Static_assert below, and the Rust test
 * `net_c_header_matches_rust_constants` checks this file's text against the
 * Rust constants. Bump SCHEMA_VERSION on any layout change.
 *
 * This object's schema is versioned independently of process.h's.
 */
#ifndef OSIRIS_NET_H
#define OSIRIS_NET_H

#include "vmlinux_min.h"

#define SCHEMA_VERSION 1
#define KIND_NET_CONNECT 3
#define KIND_NET_ACCEPT 4
#define KIND_NET_CLOSE 5
#define AF_INET 2
#define AF_INET6 10
#define DIR_OUTBOUND 1
#define DIR_INBOUND 2
#define COMM_LEN 16

/* Same header as process.h's; the two headers are never included together. */
struct record_header {
	__u32 schema_version;
	__u32 kind;
};

/*
 * Ports in host byte order. Addresses in network byte order; an IPv4
 * address fills the first 4 bytes and the other 12 are zero.
 */
struct net_record {
	struct record_header hdr;   /*  0 */
	__u32 pid;                  /*  8: owner tgid */
	__u32 uid;                  /* 12: owner uid */
	__u64 ktime_ns;             /* 16: bpf_ktime_get_ns() at emit */
	char comm[COMM_LEN];        /* 24: owner's group-leader comm */
	__u16 family;               /* 40: AF_INET or AF_INET6 */
	__u16 lport;                /* 42 */
	__u16 rport;                /* 44 */
	__u8 direction;             /* 46: DIR_OUTBOUND or DIR_INBOUND */
	__u8 _pad;                  /* 47 */
	__u8 laddr[16];             /* 48 */
	__u8 raddr[16];             /* 64 */
	__u32 exe_dev;              /* 80: owner exe inode's i_sb->s_dev (kernel dev_t), 0 = unknown */
	__u32 _pad2;                /* 84 */
	__u64 exe_ino;              /* 88: owner exe inode's i_ino, 0 = unknown */
};

_Static_assert(sizeof(struct record_header) == 8, "record_header size");
_Static_assert(sizeof(struct net_record) == 96, "net_record size");
_Static_assert(__builtin_offsetof(struct net_record, pid) == 8, "net pid");
_Static_assert(__builtin_offsetof(struct net_record, uid) == 12, "net uid");
_Static_assert(__builtin_offsetof(struct net_record, ktime_ns) == 16, "net ktime_ns");
_Static_assert(__builtin_offsetof(struct net_record, comm) == 24, "net comm");
_Static_assert(__builtin_offsetof(struct net_record, family) == 40, "net family");
_Static_assert(__builtin_offsetof(struct net_record, lport) == 42, "net lport");
_Static_assert(__builtin_offsetof(struct net_record, rport) == 44, "net rport");
_Static_assert(__builtin_offsetof(struct net_record, direction) == 46, "net direction");
_Static_assert(__builtin_offsetof(struct net_record, laddr) == 48, "net laddr");
_Static_assert(__builtin_offsetof(struct net_record, raddr) == 64, "net raddr");
_Static_assert(__builtin_offsetof(struct net_record, exe_dev) == 80, "net exe_dev");
_Static_assert(__builtin_offsetof(struct net_record, exe_ino) == 88, "net exe_ino");

#endif /* OSIRIS_NET_H */
