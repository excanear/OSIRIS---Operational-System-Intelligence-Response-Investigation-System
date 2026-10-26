/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Minimal hand-declared kernel types for the OSIRIS BPF programs.
 *
 * This replaces a generated multi-megabyte vmlinux.h. Only the fields the
 * programs read are declared. Every struct carries preserve_access_index so
 * clang emits CO-RE relocations: field offsets are resolved against the
 * running kernel's BTF at load time, so declaration order and the omitted
 * fields do not matter, but FIELD NAMES MUST MATCH THE KERNEL'S BTF NAMES.
 *
 * It also supplies the base integer typedefs normally provided by
 * <linux/types.h>, so the build needs no kernel UAPI or multiarch asm
 * headers -- only libbpf's <bpf/bpf_helpers.h> and <bpf/bpf_core_read.h>.
 */
#ifndef OSIRIS_VMLINUX_MIN_H
#define OSIRIS_VMLINUX_MIN_H

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __s8 s8;
typedef __u16 u16;
typedef __s16 s16;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;
typedef __s64 s64;

typedef int pid_t;
typedef __u32 uid_t;
typedef __u32 gid_t;
typedef unsigned short umode_t;
typedef unsigned int fmode_t;
/* Kernel-internal dev_t: MAJOR = dev >> 20, MINOR = dev & 0xfffff. */
typedef __u32 dev_t;

/* include/linux/types.h; the kernel's BTF has the same anonymous struct. */
typedef struct {
	int counter;
} __attribute__((preserve_access_index)) atomic_t;

/* include/linux/uidgid.h: kernel-global (init_user_ns) ids. */
typedef struct {
	uid_t val;
} __attribute__((preserve_access_index)) kuid_t;

typedef struct {
	gid_t val;
} __attribute__((preserve_access_index)) kgid_t;

/* Subset of enum bpf_map_type (include/uapi/linux/bpf.h); values are ABI. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* bpf_map_update_elem() flags (include/uapi/linux/bpf.h); values are ABI. */
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* Map creation flag (include/uapi/linux/bpf.h); value is ABI. */
#define BPF_F_NO_PREALLOC (1U << 0)

struct super_block {
	dev_t s_dev;
} __attribute__((preserve_access_index));

struct inode {
	umode_t i_mode;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

/*
 * include/linux/dcache.h. In the kernel `len` sits in an anonymous struct
 * inside a union with hash_len; CO-RE matching descends into anonymous
 * members by name, so it is declared flat here.
 */
struct qstr {
	u32 len;
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	/* NULL for a negative dentry (e.g. the target of a create). */
	struct inode *d_inode;
} __attribute__((preserve_access_index));

/* include/linux/mount.h: the public part of a mount. */
struct vfsmount {
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

/*
 * fs/mount.h (kernel-internal, but in BTF): `mnt` is embedded, so
 * container_of(vfsmount, struct mount, mnt) gives the struct mount. The
 * root of a mount tree (or a detached mount) has mnt_parent == itself.
 */
struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
} __attribute__((preserve_access_index));

/* include/linux/path.h */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

/* include/linux/fs_struct.h */
struct fs_struct {
	struct path root;
} __attribute__((preserve_access_index));

struct file {
	/* FMODE_* bits; the values are #defines in include/linux/fs.h. */
	fmode_t f_mode;
	struct path f_path;
	struct inode *f_inode;
	/* For a socket file: its struct socket (net/socket.c sock_alloc_file). */
	void *private_data;
} __attribute__((preserve_access_index));

/* include/linux/fdtable.h. Both pointers below are __rcu in the kernel. */
struct fdtable {
	unsigned int max_fds;
	struct file **fd;
} __attribute__((preserve_access_index));

struct files_struct {
	struct fdtable *fdt;
} __attribute__((preserve_access_index));

/* include/uapi/linux/in6.h */
struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
} __attribute__((preserve_access_index));

/*
 * include/net/sock.h. In the kernel skc_daddr/skc_rcv_saddr and
 * skc_dport/skc_num sit in anonymous structs inside unions; CO-RE matching
 * descends into anonymous members by name, so they are declared flat here.
 * The two v6 addresses exist only with CONFIG_IPV6 (net.bpf.c checks them
 * with bpf_core_field_exists before use).
 */
struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	/* volatile in the kernel; CO-RE ignores qualifiers. */
	unsigned char skc_state;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct socket;

struct sock {
	struct sock_common __sk_common;
	/* A plain u16 since Linux 5.6 (an 8-bit bitfield before). */
	u16 sk_protocol;
	struct socket *sk_socket;
} __attribute__((preserve_access_index));

/* include/linux/net.h */
struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

/* mm->arg_start/arg_end live in an anonymous struct inside mm_struct;
 * CO-RE field matching descends into anonymous members by name. */
struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
	/* The executable mapped by the last exec (an __rcu pointer). */
	struct file *exe_file;
} __attribute__((preserve_access_index));

/* Shared by every thread of a thread group (include/linux/sched/signal.h). */
struct signal_struct {
	/* Threads that have not yet passed do_exit()'s group_dead test. */
	atomic_t live;
	/* SIGNAL_* flags; SIGNAL_GROUP_EXIT is defined in process.bpf.c. */
	unsigned int flags;
	/* Wait status of a group exit (exit_group(), fatal signal). */
	int group_exit_code;
} __attribute__((preserve_access_index));

struct task_struct {
	pid_t pid;
	pid_t tgid;
	int exit_code;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct mm_struct *mm;
	struct signal_struct *signal;
	struct files_struct *files;
	/* The task's root and cwd; NULL once exit_fs() has run. */
	struct fs_struct *fs;
	char comm[16];
	/* Boot-based start time in ns; present since Linux 5.5. */
	u64 start_boottime;
} __attribute__((preserve_access_index));

/*
 * arch/x86/include/asm/ptrace.h, x86_64 (the fs object is x86_64-only).
 * <bpf/bpf_tracing.h> reads kprobe arguments from di, si, dx, cx, r8 when
 * __VMLINUX_H__ is defined (fs.bpf.c defines it). cs and ss (unions since
 * FRED, 6.9) are never read and are omitted; with preserve_access_index
 * the fields that are read are relocated by name.
 */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long flags;
	unsigned long sp;
} __attribute__((preserve_access_index));

/* Common tracepoint record header (include/linux/trace_events.h). */
struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
} __attribute__((preserve_access_index));

/*
 * sched:sched_process_exec record. `__data_loc_filename` is a __data_loc
 * descriptor: low 16 bits = offset of the string from the start of the
 * record, high 16 bits = its length.
 */
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
} __attribute__((preserve_access_index));

/*
 * sock:inet_sock_set_state record (include/trace/events/sock.h; protocol
 * is __u16 since Linux 5.6). Ports are host order (the tracepoint applies
 * ntohs); saddr/daddr are inet_saddr/inet_daddr and the v6 arrays the v6
 * addresses (IPv4-mapped for AF_INET sockets).
 */
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
} __attribute__((preserve_access_index));

/*
 * raw_syscalls:sys_exit record. A syscalls:sys_exit_<name> record is
 * struct syscall_trace_exit { ent; int nr; long ret; } (kernel/trace/
 * trace.h), whose ret sits at the same offset (16 on 64-bit) as this
 * struct's, so this BTF type serves both (the libbpf-tools convention).
 */
struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long id;
	long ret;
	char __data[0];
} __attribute__((preserve_access_index));

#endif /* OSIRIS_VMLINUX_MIN_H */
