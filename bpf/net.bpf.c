// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * OSIRIS TCP connect/accept/close BPF program (CO-RE, built by
 * tools/ebpf/build.sh, loaded by the Rust `aya` loader in crates/osiris-ebpf
 * as NET_OBJECT).
 *
 * Emits fixed-size struct net_record (bpf/net.h) into the EVENTS ring buffer:
 *   handle_state         tp/sock/inet_sock_set_state  -> CONNECT, CLOSE
 *   handle_accept4_exit  tp/syscalls/sys_exit_accept4 -> ACCEPT
 *   handle_accept_exit   tp/syscalls/sys_exit_accept  -> ACCEPT
 *
 * Ownership: a socket's owner (tgid, uid, comm, exe identity, direction) is
 * captured once, in the task context of connect() or accept(), into SOCKS
 * keyed by the struct sock pointer. CONNECT and CLOSE fire in softirq (or
 * in whatever task happens to run), so their owner always comes from SOCKS
 * and their tuple from the tracepoint record -- never from `current`.
 *
 * State logic (TCP only, AF_INET/AF_INET6):
 *   CLOSE    -> SYN_SENT     track the connecting task as owner (outbound);
 *                            no event yet (the source port may be unset)
 *   SYN_SENT -> ESTABLISHED  tracked: emit CONNECT
 *   SYN_SENT -> CLOSE        failed connect: forget it, emit nothing
 *   any      -> CLOSE        tracked: emit CLOSE, then forget it
 * accept()/accept4() returning fd >= 0: resolve the fd to its sock, emit
 * ACCEPT and track it (inbound). Sockets of the tgid in SELF_TGID[0] (the
 * agent; 0 = unset) are never tracked, so none of their events is emitted;
 * their connect/accept also removes any stale entry left at that address.
 * A failed ring-buffer reservation increments DROPS[0].
 *
 * Verifier notes (target: Linux 5.15+, privileged load):
 *  - every reservation is a constant sizeof(struct net_record) and is
 *    submitted on every path after a successful reserve;
 *  - no loops; the fd lookup is bounded by fdt->max_fds and every kernel
 *    pointer is read with the fault-tolerant probe-read helpers;
 *  - the tracepoint's address arrays are copied with bpf_core_read (the
 *    ctx pointer plus a relocated offset passed as the helper's
 *    ARG_ANYTHING source), the scalar fields are direct ctx loads.
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "net.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Record schema version, read from .rodata by the loader before load. */
const volatile __u32 schema_version = SCHEMA_VERSION;

/* include/uapi/linux/in.h and include/net/tcp_states.h; values are ABI. */
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} SELF_TGID SEC(".maps");

/* A tracked socket's owner, copied whole at connect/accept time. */
struct sock_owner {
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	__u32 exe_dev;
	__u8 direction;
	__u8 _pad[3];
	__u64 exe_ino;
};

/*
 * Tracked sockets, keyed by the struct sock pointer. LRU: when the map
 * fills, a least recently used entry is evicted and only that
 * connection's CLOSE is lost. The kernel's LRU keeps per-CPU free lists,
 * so eviction can start somewhat before 65 536 entries are live.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct sock_owner);
} SOCKS SEC(".maps");

/* True when `tgid` is the agent's own (SELF_TGID[0], 0 = unset). */
static __always_inline int is_self(__u32 tgid)
{
	__u32 key = 0;
	__u32 *self = bpf_map_lookup_elem(&SELF_TGID, &key);

	return self && *self != 0 && *self == tgid;
}

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

/*
 * The calling task as a socket owner. Called only from process context
 * (connect() via CLOSE->SYN_SENT, the accept syscalls' exit). The exe
 * identity is mm->exe_file's inode, as in process.bpf.c; a kernel thread
 * (no mm) or a failed read leaves 0 = unknown. The comm is the thread-group
 * leader's (what /proc/<pid>/comm shows and what exec/exit records carry),
 * not the calling thread's: connect() and accept() often run on named
 * worker threads. A failed read leaves it zero-filled.
 */
static __always_inline void owner_from_current(struct sock_owner *o, __u32 tgid,
					       __u8 direction)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *exe_inode;

	__builtin_memset(o, 0, sizeof(*o));
	o->pid = tgid;
	o->uid = (__u32)bpf_get_current_uid_gid();
	BPF_CORE_READ_STR_INTO(&o->comm, task, group_leader, comm);
	o->direction = direction;
	exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (exe_inode) {
		o->exe_ino = BPF_CORE_READ(exe_inode, i_ino);
		o->exe_dev = BPF_CORE_READ(exe_inode, i_sb, s_dev);
	}
}

/*
 * Reserve a record and fill everything but family and the tuple (the
 * caller sets those); the addresses are
 * zeroed (ring-buffer memory is not), so an IPv4 tuple only writes the
 * first 4 bytes of each. NULL (and a counted drop) when the buffer is full.
 */
static __always_inline struct net_record *reserve(__u32 kind,
						  const struct sock_owner *o)
{
	struct net_record *rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);

	if (!rec) {
		count_drop();
		return 0;
	}
	rec->hdr.schema_version = SCHEMA_VERSION;
	rec->hdr.kind = kind;
	rec->pid = o->pid;
	rec->uid = o->uid;
	rec->ktime_ns = bpf_ktime_get_ns();
	__builtin_memcpy(rec->comm, o->comm, COMM_LEN);
	rec->direction = o->direction;
	rec->_pad = 0;
	rec->exe_dev = o->exe_dev;
	rec->_pad2 = 0;
	rec->exe_ino = o->exe_ino;
	__builtin_memset(rec->laddr, 0, sizeof(rec->laddr));
	__builtin_memset(rec->raddr, 0, sizeof(rec->raddr));
	return rec;
}

/* Emit `kind` for `o` with the tuple of the inet_sock_set_state record. */
static __always_inline void emit_from_tp(__u32 kind, const struct sock_owner *o,
					 struct trace_event_raw_inet_sock_set_state *ctx,
					 __u16 family)
{
	struct net_record *rec = reserve(kind, o);

	if (!rec)
		return;
	rec->family = family;
	rec->lport = ctx->sport;
	rec->rport = ctx->dport;
	if (family == AF_INET) {
		bpf_core_read(rec->laddr, 4, &ctx->saddr);
		bpf_core_read(rec->raddr, 4, &ctx->daddr);
	} else {
		bpf_core_read(rec->laddr, 16, &ctx->saddr_v6);
		bpf_core_read(rec->raddr, 16, &ctx->daddr_v6);
	}
	bpf_ringbuf_submit(rec, 0);
}

SEC("tp/sock/inet_sock_set_state")
int handle_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct sock_owner owner, *tracked;
	__u64 key;
	__u16 family;
	int oldstate, newstate;
	__u32 tgid;

	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	family = ctx->family;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	key = (__u64)(unsigned long)ctx->skaddr;
	oldstate = ctx->oldstate;
	newstate = ctx->newstate;

	if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
		/* tcp_v4_connect()/tcp_v6_connect(): the connecting task. */
		tgid = bpf_get_current_pid_tgid() >> 32;
		if (is_self(tgid)) {
			/* The agent's own connect: drop any entry left over for
			 * a previous sock at this address, so the agent's
			 * CONNECT/CLOSE are never emitted under a stale owner. */
			bpf_map_delete_elem(&SOCKS, &key);
			return 0;
		}
		owner_from_current(&owner, tgid, DIR_OUTBOUND);
		/* BPF_ANY: a stale entry for a reused sock address is replaced. */
		bpf_map_update_elem(&SOCKS, &key, &owner, BPF_ANY);
		return 0;
	}
	if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE)
		return 0;

	tracked = bpf_map_lookup_elem(&SOCKS, &key);
	if (!tracked)
		return 0;
	if (newstate == TCP_ESTABLISHED) {
		if (oldstate == TCP_SYN_SENT)
			emit_from_tp(KIND_NET_CONNECT, tracked, ctx, family);
		return 0;
	}
	/* newstate == TCP_CLOSE. A failed connect emits nothing. Every other
	 * close (including the full socket's hand-off to TIME_WAIT) emits
	 * CLOSE with the owner stored at open time; the entry goes after the
	 * last use of `tracked`. */
	if (oldstate != TCP_SYN_SENT)
		emit_from_tp(KIND_NET_CLOSE, tracked, ctx, family);
	bpf_map_delete_elem(&SOCKS, &key);
	return 0;
}

/*
 * accept()/accept4() returned `ret` in the acceptor's context: resolve the
 * new fd to its sock (current->files->fdt->fd[ret]->private_data is the
 * struct socket), emit ACCEPT with the tuple from sock_common and track it.
 * The fd is checked against fdt->max_fds; the sock must point back at the
 * socket (a fd swapped by another thread between the syscall's return and
 * this tracepoint fails that test, or is not a TCP socket).
 */
static __always_inline int on_accept_exit(long ret)
{
	struct task_struct *task;
	struct fdtable *fdt;
	struct file **fds, *file = 0;
	struct socket *sock;
	struct sock *sk;
	struct sock_owner owner;
	struct net_record *rec;
	unsigned int max_fds;
	__u16 family;
	__u64 key;
	__u32 tgid;

	if (ret < 0)
		return 0;
	tgid = bpf_get_current_pid_tgid() >> 32;

	task = (struct task_struct *)bpf_get_current_task();
	fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt)
		return 0;
	max_fds = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned long)ret >= max_fds)
		return 0;
	fds = BPF_CORE_READ(fdt, fd);
	if (!fds || bpf_probe_read_kernel(&file, sizeof(file), &fds[ret]) != 0 || !file)
		return 0;
	sock = BPF_CORE_READ(file, private_data);
	if (!sock)
		return 0;
	sk = BPF_CORE_READ(sock, sk);
	if (!sk || BPF_CORE_READ(sk, sk_socket) != sock)
		return 0;
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	key = (__u64)(unsigned long)sk;
	if (is_self(tgid)) {
		/* The agent's own accept: as for its connects, drop any entry
		 * left over for a previous sock at this address. */
		bpf_map_delete_elem(&SOCKS, &key);
		return 0;
	}

	owner_from_current(&owner, tgid, DIR_INBOUND);
	rec = reserve(KIND_NET_ACCEPT, &owner);
	if (rec) {
		rec->family = family;
		rec->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
		rec->rport = port_from_be(BPF_CORE_READ(sk, __sk_common.skc_dport));
		if (family == AF_INET) {
			bpf_core_read(rec->laddr, 4, &sk->__sk_common.skc_rcv_saddr);
			bpf_core_read(rec->raddr, 4, &sk->__sk_common.skc_daddr);
		} else if (bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
			bpf_core_read(rec->laddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
			bpf_core_read(rec->raddr, 16, &sk->__sk_common.skc_v6_daddr);
		}
		bpf_ringbuf_submit(rec, 0);
	}

	/*
	 * Tracked even when the record was dropped, so the CLOSE is still
	 * seen. Insert first, then re-read the state: a close on another CPU
	 * before the insert found no entry and will see no further
	 * transition, so the entry is removed again rather than left to
	 * attribute a later sock at this address to this owner. A close after
	 * the insert emits CLOSE and deletes it in handle_state (the delete
	 * below is then a no-op). Only CLOSE is tested: a TCP Fast Open child
	 * can be accepted while still SYN_RECV and must stay tracked.
	 */
	bpf_map_update_elem(&SOCKS, &key, &owner, BPF_ANY);
	if (BPF_CORE_READ(sk, __sk_common.skc_state) == TCP_CLOSE)
		bpf_map_delete_elem(&SOCKS, &key);
	return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int handle_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
	return on_accept_exit(ctx->ret);
}

SEC("tp/syscalls/sys_exit_accept")
int handle_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
	return on_accept_exit(ctx->ret);
}
