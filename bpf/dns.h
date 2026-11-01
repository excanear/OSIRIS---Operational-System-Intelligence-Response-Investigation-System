/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Record ABI shared between bpf/dns.bpf.c and the Rust consumer
 * (crates/osiris-ebpf/src/dns_record.rs). The two MUST stay byte-identical:
 * the Rust side pins sizes/offsets in `dns_layout_is_pinned`, this header
 * pins the same values with _Static_assert below, and the Rust test
 * `dns_c_header_matches_rust_constants` checks this file's text against the
 * Rust constants. Bump SCHEMA_VERSION on any layout change.
 *
 * This object's schema is versioned independently of the other headers'.
 */
#ifndef OSIRIS_DNS_H
#define OSIRIS_DNS_H

#include "vmlinux_min.h"

#define SCHEMA_VERSION 1
#define KIND_DNS_SEND 10
#define AF_INET 2
#define AF_INET6 10
#define COMM_LEN 16

/* Same header as process.h's; the headers are never included together. */
struct record_header {
	__u32 schema_version;
	__u32 kind;
};

/*
 * One UDP send to port 53. Ports in host byte order. Addresses in network
 * byte order; an IPv4 address fills the first 4 bytes and the other 12 are
 * zero.
 */
struct dns_record {
	struct record_header hdr;   /*  0 */
	__u32 pid;                  /*  8: sender tgid */
	__u32 tid;                  /* 12: sender thread pid */
	__u32 uid;                  /* 16: sender uid */
	__u16 family;               /* 20: AF_INET or AF_INET6 */
	__u16 lport;                /* 22 */
	__u64 ktime_ns;             /* 24: bpf_ktime_get_ns() at emit */
	char comm[COMM_LEN];        /* 32: sender's group-leader comm */
	__u32 exe_dev;              /* 48: exe inode's i_sb->s_dev (kernel dev_t), 0 = unknown */
	__u32 netns_ino;            /* 52: network namespace inode number */
	__u64 exe_ino;              /* 56: exe inode's i_ino, 0 = unknown */
	__u16 rport;                /* 64 */
	__u16 _pad;                 /* 66 */
	__u32 _pad2;                /* 68 */
	__u8 laddr[16];             /* 72 */
	__u8 raddr[16];             /* 88 */
};

_Static_assert(sizeof(struct record_header) == 8, "record_header size");
_Static_assert(sizeof(struct dns_record) == 104, "dns_record size");
_Static_assert(__builtin_offsetof(struct dns_record, pid) == 8, "dns pid");
_Static_assert(__builtin_offsetof(struct dns_record, tid) == 12, "dns tid");
_Static_assert(__builtin_offsetof(struct dns_record, uid) == 16, "dns uid");
_Static_assert(__builtin_offsetof(struct dns_record, family) == 20, "dns family");
_Static_assert(__builtin_offsetof(struct dns_record, lport) == 22, "dns lport");
_Static_assert(__builtin_offsetof(struct dns_record, ktime_ns) == 24, "dns ktime_ns");
_Static_assert(__builtin_offsetof(struct dns_record, comm) == 32, "dns comm");
_Static_assert(__builtin_offsetof(struct dns_record, exe_dev) == 48, "dns exe_dev");
_Static_assert(__builtin_offsetof(struct dns_record, netns_ino) == 52, "dns netns_ino");
_Static_assert(__builtin_offsetof(struct dns_record, exe_ino) == 56, "dns exe_ino");
_Static_assert(__builtin_offsetof(struct dns_record, rport) == 64, "dns rport");
_Static_assert(__builtin_offsetof(struct dns_record, _pad) == 66, "dns _pad");
_Static_assert(__builtin_offsetof(struct dns_record, _pad2) == 68, "dns _pad2");
_Static_assert(__builtin_offsetof(struct dns_record, laddr) == 72, "dns laddr");
_Static_assert(__builtin_offsetof(struct dns_record, raddr) == 88, "dns raddr");

#endif /* OSIRIS_DNS_H */
