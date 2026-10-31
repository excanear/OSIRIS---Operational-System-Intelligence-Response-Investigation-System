// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * OSIRIS DNS send-attribution BPF program (CO-RE, x86_64 only, built by
 * tools/ebpf/build.sh, loaded by the Rust `aya` loader in crates/osiris-ebpf
 * as DNS_OBJECT).
 *
 * Emits one fixed-size struct dns_record (bpf/dns.h) into the EVENTS ring
 * buffer per UDP send whose destination port is 53:
 *   kp_udp_sendmsg    kprobe/udp_sendmsg    -> DNS_SEND, AF_INET
 *   kp_udpv6_sendmsg  kprobe/udpv6_sendmsg  -> DNS_SEND, AF_INET6
 * User space joins these with the DNS packets it captures (AF_PACKET), by
 * (local port, remote address, remote port) and time.
 *
 * Both kprobes run in the sending task's context (the sendto/sendmsg/
 * sendmmsg/write path), so the owner comes from `current`: the tgid and
 * thread id, the uid, the thread-group leader's comm and the exe identity
 * (mm->exe_file's inode, as in net.bpf.c). The network namespace inode
 * comes from the socket.
 *
 * Destination: from msg->msg_name when msg_namelen != 0, from the socket
 * (a connected socket's peer) otherwise. The port is read first, and a
 * send to any port but 53 returns before any map access or reservation.
 * udpv6_sendmsg hands an IPv4-mapped destination (::ffff:a.b.c.d) and an
 * AF_INET msg_name to udp_sendmsg, so the v6 program returns for both and
 * such a send is reported once, as AF_INET, by the v4 program.
 *
 * Every send is emitted, the agent's own included: SELF_TGID exists only
 * because the loader sets it on every object; this program never reads it.
 * A failed ring-buffer reservation increments DROPS[0].
 *
 * Verifier notes (target: Linux 5.15+, privileged load):
 *  - every reservation is a constant sizeof(struct dns_record) and is
 *    submitted on every path after a successful reserve;
 *  - no loops; the 16-byte v6 address is checked word by word;
 *  - every kernel pointer (sk, msg, msg_name, task) is read with the
 *    fault-tolerant probe-read helpers (BPF_CORE_READ, bpf_core_read).
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
/* Makes <bpf/bpf_tracing.h> use the kernel's pt_regs names (di, si, ...). */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif
#include <bpf/bpf_tracing.h>
#include "dns.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Record schema version, read from .rodata by the loader before load. */
const volatile __u32 schema_version = SCHEMA_VERSION;

#define AF_UNSPEC 0
#define DNS_PORT 53

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} EVENTS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} DROPS SEC(".maps");

/* Set by the loader (as on every object); never read by this program. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} SELF_TGID SEC(".maps");

/* Per-CPU slot, so a plain increment is race-free. */
static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *drops = bpf_map_lookup_elem(&DROPS, &key);

	if (drops)
		*drops += 1;
}

/* Network to host order for a 16-bit port (the BPF target is bpfel). */
static __always_inline __u16 port_from_be(__be16 v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(v);
#else
	return v;
#endif
}

/* Network to host order for a 32-bit word. */
static __always_inline __u32 word_from_be(__be32 v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(v);
#else
	return v;
#endif
}

/*
 * Reserve a record and fill everything but the addresses' contents, the
 * family and the ports (the caller sets those): the owner from `current`,
 * the netns from `sk`. Both addresses are zeroed (ring-buffer memory is
 * not), so an IPv4 tuple only writes the first 4 bytes of each. NULL (and a
 * counted drop) when the buffer is full. A failed read leaves its field
 * zero (comm zero-filled, exe 0 = unknown, netns 0).
 */
static __always_inline struct dns_record *reserve(struct sock *sk)
{
	struct task_struct *task;
	struct inode *exe_inode;
	struct dns_record *rec;
	__u64 id;

	rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);
	if (!rec) {
		count_drop();
		return 0;
	}
	id = bpf_get_current_pid_tgid();
	task = (struct task_struct *)bpf_get_current_task();

	rec->hdr.schema_version = SCHEMA_VERSION;
	rec->hdr.kind = KIND_DNS_SEND;
	rec->pid = id >> 32;
	rec->tid = (__u32)id;
	rec->uid = bpf_get_current_uid_gid() & 0xffffffff;
	rec->family = 0;
	rec->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	rec->ktime_ns = bpf_ktime_get_ns();
	__builtin_memset(rec->comm, 0, COMM_LEN);
	BPF_CORE_READ_STR_INTO(&rec->comm, task, group_leader, comm);
	rec->exe_dev = 0;
	rec->exe_ino = 0;
	exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (exe_inode) {
		rec->exe_ino = BPF_CORE_READ(exe_inode, i_ino);
		rec->exe_dev = BPF_CORE_READ(exe_inode, i_sb, s_dev);
	}
	rec->netns_ino = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	rec->rport = DNS_PORT;
	rec->_pad = 0;
	rec->_pad2 = 0;
	__builtin_memset(rec->laddr, 0, sizeof(rec->laddr));
	__builtin_memset(rec->raddr, 0, sizeof(rec->raddr));
	return rec;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct sockaddr_in *usin = 0;
	struct dns_record *rec;
	__be32 daddr = 0;
	__be16 dport;

	/* The hot path: every send not to port 53 leaves here. */
	if (BPF_CORE_READ(msg, msg_namelen) != 0) {
		usin = BPF_CORE_READ(msg, msg_name);
		if (!usin)
			return 0;
		dport = BPF_CORE_READ(usin, sin_port);
	} else {
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	}
	if (port_from_be(dport) != DNS_PORT)
		return 0;

	if (usin)
		daddr = BPF_CORE_READ(usin, sin_addr.s_addr);
	else
		daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

	rec = reserve(sk);
	if (!rec)
		return 0;
	rec->family = AF_INET;
	bpf_core_read(rec->laddr, 4, &sk->__sk_common.skc_rcv_saddr);
	__builtin_memcpy(rec->raddr, &daddr, 4);
	bpf_ringbuf_submit(rec, 0);
	return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kp_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct sockaddr_in6 *sin6 = 0;
	struct dns_record *rec;
	__be32 daddr[4] = {};
	__be16 dport;

	/* The hot path: every send not to port 53 leaves here. sin_port and
	 * sin6_port share an offset, so an AF_INET msg_name is tested the
	 * same way before it is turned away below. */
	if (BPF_CORE_READ(msg, msg_namelen) != 0) {
		sin6 = BPF_CORE_READ(msg, msg_name);
		if (!sin6)
			return 0;
		dport = BPF_CORE_READ(sin6, sin6_port);
	} else {
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	}
	if (port_from_be(dport) != DNS_PORT)
		return 0;
	/* The v6 addresses exist only with CONFIG_IPV6, as does this
	 * program's target. */
	if (!bpf_core_field_exists(sk->__sk_common.skc_v6_daddr) ||
	    !bpf_core_field_exists(sk->__sk_common.skc_v6_rcv_saddr))
		return 0;

	if (sin6) {
		switch (BPF_CORE_READ(sin6, sin6_family)) {
		case AF_INET6:
			bpf_core_read(daddr, sizeof(daddr), &sin6->sin6_addr);
			break;
		case AF_UNSPEC:
			/* udpv6_sendmsg drops the name: the socket's peer. */
			sin6 = 0;
			break;
		default:
			/* AF_INET: handed to udp_sendmsg (reported there);
			 * anything else is rejected with -EINVAL. */
			return 0;
		}
	}
	if (!sin6)
		bpf_core_read(daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr);
	/* ::ffff:a.b.c.d goes to udp_sendmsg, which reports it as AF_INET. */
	if (daddr[0] == 0 && daddr[1] == 0 && word_from_be(daddr[2]) == 0x0000ffff)
		return 0;

	rec = reserve(sk);
	if (!rec)
		return 0;
	rec->family = AF_INET6;
	bpf_core_read(rec->laddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
	__builtin_memcpy(rec->raddr, daddr, 16);
	bpf_ringbuf_submit(rec, 0);
	return 0;
}
