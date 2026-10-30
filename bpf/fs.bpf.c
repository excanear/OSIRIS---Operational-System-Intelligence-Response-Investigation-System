// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * OSIRIS filesystem create/write/delete/rename BPF program (CO-RE, built by
 * tools/ebpf/build.sh, loaded by the Rust `aya` loader in crates/osiris-ebpf
 * as FS_OBJECT). x86_64 only: the kprobe arguments are read from x86_64
 * pt_regs (BPF_KPROBE with -D__TARGET_ARCH_x86).
 *
 * Emits fixed-size struct fs_record (bpf/fs.h) into the EVENTS ring buffer,
 * one per SUCCESSFUL operation under a watched directory:
 *
 *   kprobe security_path_mknod   -> CREATE (regular files only: open(O_CREAT),
 *                                   creat, mknod with S_IFREG or type 0)
 *   kprobe security_path_mkdir   -> CREATE
 *   kprobe security_path_unlink  -> DELETE
 *   kprobe security_path_rmdir   -> DELETE
 *   kprobe security_path_rename  -> RENAME (path = destination,
 *                                   old_path = source; RENAME_EXCHANGE is
 *                                   one RENAME src -> dst)
 *   kprobe security_file_open    -> WRITE (FMODE_WRITE on a regular file)
 *   kprobe security_path_truncate, security_file_truncate (6.2+, optional)
 *                                -> WRITE
 *
 * Stage / clear / emit (only successful operations are reported):
 *  - a hook builds the record (process fields, file fields, path(s)) in the
 *    per-CPU SCRATCH value and stages it in PENDING under the thread's
 *    pid_tgid, only if the thread has no entry yet (the first hook in a
 *    syscall wins: open(O_CREAT) of a new file is CREATE, not CREATE +
 *    WRITE). A failed insert other than "already staged" counts in DROPS;
 *  - security_file_open may fill in the inode fields of a staged CREATE
 *    (the inode does not exist yet at security_path_mknod time); it never
 *    changes the staged kind;
 *  - tp/syscalls/sys_enter_<sc> deletes the thread's entry, so an entry seen
 *    at exit was staged during this same syscall;
 *  - tp/syscalls/sys_exit_<sc> copies the entry into a ring-buffer record
 *    when ret >= 0 (setting ret and ktime_ns) and deletes it in every case;
 *  - tp/sched/sched_process_exit deletes the exiting thread's entry.
 * Threads of the tgid in SELF_TGID[0] (the agent; 0 = unset) never stage.
 *
 * Watched-path filter: WATCH holds the (i_sb->s_dev, i_ino) of each watched
 * directory. The walk from the operand's dentry towards the task's root
 * (current->fs->root) looks every positive dentry up in WATCH, mount roots
 * included, crossing mounts through container_of(vfsmount, struct mount,
 * mnt)->mnt_parent / mnt_mountpoint. With WATCH_FLAGS[0] bit 0 set (an
 * inode-only key exists, for btrfs/overlayfs) a miss is retried as
 * (0, i_ino). A rename matches if the source or the destination side does.
 * The same walk writes the path right to left into SCRATCH.buf. Name
 * writes stop at the task's root (the path is then complete, as d_path()
 * shows it to the task) or when a name does not fit; the walk itself goes
 * on WATCH-checking the ancestors, crossing mounts, until the top of the
 * mount tree (or a detached mount's root) or MAX_COMPONENTS steps. So a
 * long path, a chroot or pivot_root inside a watched tree, or a write
 * through a detached mount of a watched directory cannot hide an
 * operation. Only a walk that reached the task's root with every name
 * written is complete; any other path (it did not fit, the walk ran out of
 * steps, or the operand is outside the task's root: a detached mount, an
 * fd opened before a chroot) is kept as its tail, without a leading '/',
 * and flagged truncated. Not covered: a bind mount of a watched
 * directory's SUBdirectory (the walk crosses from that mount's root to
 * its mountpoint and never visits the watched ancestor).
 *
 * Verifier notes (target: Linux 5.15+, privileged load):
 *  - every ring-buffer reservation is a constant sizeof(struct fs_record),
 *    filled by one constant-size bpf_probe_read_kernel from the PENDING
 *    value, and submitted (or discarded) on every path;
 *  - the walk is a bounded loop that is NOT unrolled (#pragma clang loop
 *    unroll(disable); bounded loops need 5.3+, bpf_loop is not used because
 *    it needs 5.17+). Every value carried from one step to the next (the
 *    current dentry and mount, the write position, the matched / complete
 *    flags, the root) lives in SCRATCH.w and is reloaded with a volatile
 *    access. A scalar loaded from map memory is unknown and ends precision
 *    backtracking, so the only state that differs between iterations is the
 *    loop counter: all branches of one step reach the next loop head in
 *    equal states and are pruned there. Cost is linear in MAX_COMPONENTS
 *    (one body per iteration) instead of exponential in the branches, as
 *    the fully unrolled walk was ("BPF program is too large");
 *  - everything is __always_inline: no BPF-to-BPF calls, which on 5.15
 *    would make precision backtracking give up and mark every scalar
 *    precise;
 *  - every variable buffer offset and length is masked after a compiler
 *    barrier (offsets with PATH_CAP - 1, name lengths with NAME_MASK), and
 *    SCRATCH.buf is 2 * PATH_CAP bytes, so offset + length is always
 *    inside it; the semantic checks (length <= NAME_MAX, length + 1 <=
 *    remaining room) come first, so the masks never change a value;
 *  - the path is copied out with a constant PATH_CAP-byte read starting at
 *    the path's first byte: SCRATCH.buf[PATH_CAP..] is never written and
 *    stays zero, so bytes past the path are zero in the record;
 *  - every kernel pointer is read with the fault-tolerant probe-read
 *    helpers (BPF_CORE_READ).
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
/* Makes <bpf/bpf_tracing.h> use the kernel's pt_regs names (di, si, ...). */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif
#include <bpf/bpf_tracing.h>
#include "fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Record schema version, read from .rodata by the loader before load. */
const volatile __u32 schema_version = SCHEMA_VERSION;

#ifndef EEXIST
#define EEXIST 17
#endif

/* include/uapi/linux/stat.h; values are ABI. */
#define S_IFMT 00170000
#define S_IFREG 0100000

/*
 * include/linux/fs.h; a #define, not in BTF, so hard-coded. FMODE_WRITE is
 * 0x2 on every kernel (OPEN_FMODE maps O_WRONLY/O_RDWR onto it).
 */
#define FMODE_WRITE 0x2

/* include/uapi/linux/limits.h */
#define NAME_MAX 255
#define NAME_MASK 0xff
#define CAP_MASK (PATH_CAP - 1)
#define MAX_COMPONENTS 32

_Static_assert((PATH_CAP & (PATH_CAP - 1)) == 0, "PATH_CAP must be a power of two");
_Static_assert(PATH_CAP - 1 + NAME_MASK < 2 * PATH_CAP, "masked name write fits SCRATCH.buf");

/* Hide a value from the compiler so the masked register is the one used. */
#define opaque(x) asm volatile("" : "+r"(x))

/* Forced memory accesses for the walk state (never cached in a register). */
#define LOAD(x) (*(volatile __typeof__(x) *)&(x))
#define STORE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
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

/* Staged operations, keyed by pid_tgid (thread); see the header comment. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct fs_record);
} PENDING SEC(".maps");

/* Same layout as the Rust loader's WatchKey; no implicit padding. */
struct watch_key {
	__u32 dev;
	__u32 _pad;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct watch_key);
	__type(value, __u8);
} WATCH SEC(".maps");

/* Bit 0: at least one inode-only (dev = 0) WATCH key exists. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} WATCH_FLAGS SEC(".maps");

/*
 * The walk's loop-carried state. It is kept in SCRATCH, not in registers or
 * on the stack, and only touched through LOAD/STORE; see the verifier notes
 * in the header comment.
 */
struct walk_state {
	__u64 d;          /* current dentry */
	__u64 m;          /* current vfsmount */
	__u64 root_d;     /* current->fs->root.dentry; 0 without an fs_struct */
	__u64 root_m;     /* current->fs->root.mnt */
	__u64 cur;        /* first written byte of buf; PATH_CAP = nothing yet */
	__u32 inode_only; /* WATCH_FLAGS[0] bit 0 */
	__u32 matched;    /* a watched directory was seen (since walk_begin) */
	__u32 complete;   /* reached the task root with every name written */
	__u32 full;       /* name writes stopped (no fit, or past the root) */
};

/*
 * Per-CPU work area: the record being staged, the walk state, and the path
 * buffer the walk writes right to left into buf[0..PATH_CAP).
 * buf[PATH_CAP..] is never written (zero) and only exists so masked
 * accesses and the constant-size copy-out stay inside the value. Kprobe
 * programs do not nest on a CPU.
 */
struct scratch {
	struct fs_record rec;
	struct walk_state w;
	__u8 buf[2 * PATH_CAP];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} SCRATCH SEC(".maps");

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

/* WATCH_FLAGS[0] bit 0: retry lookups as (0, ino). */
static __always_inline __u32 inode_only_keys(void)
{
	__u32 key = 0;
	__u32 *flags = bpf_map_lookup_elem(&WATCH_FLAGS, &key);

	return flags ? (*flags & 1) : 0;
}

/* Whether `d` is a watched directory (negative dentries never are). */
static __always_inline int is_watched(struct dentry *d, __u32 inode_only)
{
	struct watch_key key = {};
	struct inode *inode = BPF_CORE_READ(d, d_inode);

	if (!inode)
		return 0;
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	key.ino = BPF_CORE_READ(inode, i_ino);
	if (bpf_map_lookup_elem(&WATCH, &key))
		return 1;
	if (!inode_only)
		return 0;
	key.dev = 0;
	return bpf_map_lookup_elem(&WATCH, &key) != 0;
}

/* offsetof(struct mount, mnt) on the running kernel (CO-RE relocated). */
static __always_inline __u64 mount_mnt_off(void)
{
	return __builtin_preserve_field_info(((struct mount *)0)->mnt,
					     BPF_FIELD_BYTE_OFFSET);
}

/* container_of(vfsmnt, struct mount, mnt). */
static __always_inline struct mount *real_mount(struct vfsmount *vfsmnt)
{
	return (struct mount *)((char *)vfsmnt - mount_mnt_off());
}

/* &mnt->mnt: the struct vfsmount embedded in `mnt`. */
static __always_inline struct vfsmount *mount_vfs(struct mount *mnt)
{
	return (struct vfsmount *)((char *)mnt + mount_mnt_off());
}

/*
 * Start the walk(s) of one hook: record the task's root (current->fs->root;
 * zero when it has no fs_struct: the root is then never met, the walk ends
 * at the top of the mount tree and the path is reported as a tail)
 * and the inode-only flag, and clear `matched`.
 */
static __always_inline void walk_begin(struct scratch *s)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	__u64 root_d = 0, root_m = 0;

	if (fs) {
		root_d = (__u64)BPF_CORE_READ(fs, root.dentry);
		root_m = (__u64)BPF_CORE_READ(fs, root.mnt);
	}
	STORE(s->w.root_d, root_d);
	STORE(s->w.root_m, root_m);
	STORE(s->w.inode_only, inode_only_keys());
	STORE(s->w.matched, 0);
}

/*
 * One step at (s->w.d, s->w.m): check WATCH; at the task's root mark the
 * path complete (if every name fit) and stop writing names; then either
 * stop (returns 1: the top of the mount tree, a detached mount's root or a
 * disconnected dentry), cross to the mountpoint in the parent mount, or
 * prepend "/name" to the path (unless writes stopped) and move to the
 * parent dentry (returns 0). Reads and writes its state only through
 * LOAD/STORE, so nothing survives in a register to the next step.
 */
static __always_inline int walk_step(struct scratch *s)
{
	struct dentry *d = (struct dentry *)LOAD(s->w.d);
	struct vfsmount *m = (struct vfsmount *)LOAD(s->w.m);
	struct dentry *parent;
	const unsigned char *name;
	__u64 cur, len, pos;

	if (!LOAD(s->w.matched) && is_watched(d, LOAD(s->w.inode_only)))
		STORE(s->w.matched, 1);
	if ((__u64)d == LOAD(s->w.root_d) && (__u64)m == LOAD(s->w.root_m)) {
		/* The task's root: the path written so far is the one the
		 * task sees. The walk goes on past it (a chroot or
		 * pivot_root inside a watched tree must not hide the
		 * operation), only WATCH-checking from here on. */
		if (!LOAD(s->w.full))
			STORE(s->w.complete, 1);
		STORE(s->w.full, 1);
	}
	if (d == BPF_CORE_READ(m, mnt_root)) {
		/* A mount root: continue at the mountpoint in the parent
		 * mount; the mount root itself has no name of its own. */
		struct mount *mnt = real_mount(m);
		struct mount *up = BPF_CORE_READ(mnt, mnt_parent);

		if (!up || up == mnt) {
			/* The top of the mount tree, or a detached mount
			 * (open_tree(OPEN_TREE_CLONE), lazily unmounted):
			 * nothing above. `complete` is left as it is: unless
			 * the task's root was passed on the way, the operand
			 * is outside it and the path is only a tail. */
			return 1;
		}
		STORE(s->w.d, (__u64)BPF_CORE_READ(mnt, mnt_mountpoint));
		STORE(s->w.m, (__u64)mount_vfs(up));
		return 0;
	}
	parent = BPF_CORE_READ(d, d_parent);
	if (!parent || parent == d)
		return 1; /* disconnected: not a path from the root */
	/* Move up first: once writes stopped (a name did not fit, or past
	 * the task's root) the ancestors are still WATCH-checked (a long
	 * path or a chroot must not hide an event), only their names are no
	 * longer written. */
	STORE(s->w.d, (__u64)parent);
	if (LOAD(s->w.full))
		return 0;
	len = BPF_CORE_READ(d, d_name.len);
	cur = LOAD(s->w.cur);
	if (len > NAME_MAX || len + 1 > cur) {
		/* Does not fit: keep the tail written so far. */
		STORE(s->w.full, 1);
		return 0;
	}
	name = BPF_CORE_READ(d, d_name.name);
	cur -= len;
	pos = cur;
	opaque(pos);
	opaque(len);
	/* Writes stay in buf[0..PATH_CAP): buf[PATH_CAP..] must never be
	 * written, because stage_one's old_path zero-fill reads from it. */
	bpf_probe_read_kernel(&s->buf[pos & CAP_MASK], len & NAME_MASK, name);
	cur -= 1;
	pos = cur;
	opaque(pos);
	s->buf[pos & CAP_MASK] = '/';
	STORE(s->w.cur, cur);
	return 0;
}

/*
 * Walk from `d` (on mount `m`) upwards, checking WATCH at every dentry
 * (s->w.matched is sticky from walk_begin, so a rename's two walks OR) and
 * writing "/name" components right to left into s->buf[0..PATH_CAP).
 * Copies the result into `dst` (PATH_CAP bytes, zero past the path) and
 * stores its length and truncation flag through `len_out` / `trunc_out`.
 * The loop is deliberately not unrolled; see the header comment.
 */
static __always_inline void walk_path(struct scratch *s, struct dentry *d,
				      struct vfsmount *m, __u8 *dst,
				      __u16 *len_out, __u8 *trunc_out)
{
	__u64 start;
	int i;

	STORE(s->w.d, (__u64)d);
	STORE(s->w.m, (__u64)m);
	STORE(s->w.cur, PATH_CAP);
	STORE(s->w.complete, 0);
	STORE(s->w.full, 0);

#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_COMPONENTS; i++) {
		if (walk_step(s))
			break;
	}

	start = LOAD(s->w.cur);
	/* `complete` is only ever set while every name had fit. */
	if (LOAD(s->w.complete)) {
		if (start == PATH_CAP) {
			/* The operand is the root itself. */
			start = PATH_CAP - 1;
			s->buf[CAP_MASK] = '/';
		}
		*trunc_out = 0;
	} else {
		/* A tail is never rendered as absolute: drop its '/'. */
		start = start < PATH_CAP ? start + 1 : PATH_CAP;
		*trunc_out = 1;
	}
	opaque(start);
	start &= 2 * PATH_CAP - 1;
	*len_out = (__u16)(PATH_CAP - start);
	bpf_probe_read_kernel(dst, PATH_CAP, &s->buf[start]);
}

/* Copy `inode`'s identity into `r` (has_inode = 1), if there is one. */
static __always_inline void fill_inode(struct fs_record *r, struct inode *inode)
{
	if (!inode)
		return;
	r->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	r->ino = BPF_CORE_READ(inode, i_ino);
	r->mode = BPF_CORE_READ(inode, i_mode);
	r->owner_uid = BPF_CORE_READ(inode, i_uid.val);
	r->owner_gid = BPF_CORE_READ(inode, i_gid.val);
	r->has_inode = 1;
}

/*
 * Every field of `r` except the paths, their lengths and truncation flags
 * (written by walk_path and the callers), for the calling task. The exe
 * identity is mm->exe_file's inode and the comm the thread-group leader's,
 * as in net.bpf.c; a kernel thread or a failed read leaves them 0 / empty.
 */
static __always_inline void fill_actor(struct fs_record *r, __u32 kind, __u64 id)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct inode *exe_inode;

	r->hdr.schema_version = SCHEMA_VERSION;
	r->hdr.kind = kind;
	r->pid = id >> 32;
	r->ppid = BPF_CORE_READ(task, real_parent, tgid);
	r->uid = (__u32)bpf_get_current_uid_gid();
	r->ret = 0;
	r->ktime_ns = 0;
	__builtin_memset(r->comm, 0, COMM_LEN);
	BPF_CORE_READ_STR_INTO(&r->comm, task, group_leader, comm);
	r->exe_dev = 0;
	r->exe_ino = 0;
	exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (exe_inode) {
		r->exe_ino = BPF_CORE_READ(exe_inode, i_ino);
		r->exe_dev = BPF_CORE_READ(exe_inode, i_sb, s_dev);
	}
	r->dev = 0;
	r->ino = 0;
	r->mode = 0;
	r->owner_uid = 0;
	r->owner_gid = 0;
	r->has_inode = 0;
	r->_pad = 0;
	r->_pad2 = 0;
}

/*
 * The SCRATCH area for a new staged operation of thread `id`, or NULL when
 * the thread is the agent's or already has a staged entry (first hook
 * wins).
 */
static __always_inline struct scratch *stage_begin(__u64 id)
{
	__u32 key = 0;

	if (is_self(id >> 32))
		return 0;
	if (bpf_map_lookup_elem(&PENDING, &id))
		return 0;
	return bpf_map_lookup_elem(&SCRATCH, &key);
}

/* Insert the built record; a failure other than "already staged" drops. */
static __always_inline void stage_commit(struct scratch *s, __u64 id)
{
	long err = bpf_map_update_elem(&PENDING, &id, &s->rec, BPF_NOEXIST);

	if (err && err != -EEXIST)
		count_drop();
}

/* Stage `kind` on `dentry` (on mount `mnt`), with `inode`'s fields if any. */
static __always_inline void stage_one(__u32 kind, struct dentry *dentry,
				      struct vfsmount *mnt, struct inode *inode)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct scratch *s;

	s = stage_begin(id);
	if (!s || !dentry || !mnt)
		return;
	walk_begin(s);
	walk_path(s, dentry, mnt, s->rec.path, &s->rec.path_len,
		  &s->rec.path_truncated);
	if (!LOAD(s->w.matched))
		return;
	fill_actor(&s->rec, kind, id);
	/* old_path is unused: a copy from the never-written zero half. */
	s->rec.old_path_len = 0;
	s->rec.old_path_truncated = 0;
	bpf_probe_read_kernel(s->rec.old_path, PATH_CAP, &s->buf[PATH_CAP]);
	fill_inode(&s->rec, inode);
	stage_commit(s, id);
}

SEC("kprobe/security_path_mknod")
int BPF_KPROBE(kp_path_mknod, struct path *dir, struct dentry *dentry,
	       umode_t mode)
{
	umode_t type = mode & S_IFMT;

	/* Type 0 is a regular file for mknod(2); fifos, sockets and device
	 * nodes are ignored. */
	if (type != 0 && type != S_IFREG)
		return 0;
	stage_one(KIND_FS_CREATE, dentry, BPF_CORE_READ(dir, mnt), 0);
	return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(kp_path_mkdir, struct path *dir, struct dentry *dentry)
{
	stage_one(KIND_FS_CREATE, dentry, BPF_CORE_READ(dir, mnt), 0);
	return 0;
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(kp_path_unlink, struct path *dir, struct dentry *dentry)
{
	stage_one(KIND_FS_DELETE, dentry, BPF_CORE_READ(dir, mnt),
		  BPF_CORE_READ(dentry, d_inode));
	return 0;
}

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(kp_path_rmdir, struct path *dir, struct dentry *dentry)
{
	stage_one(KIND_FS_DELETE, dentry, BPF_CORE_READ(dir, mnt),
		  BPF_CORE_READ(dentry, d_inode));
	return 0;
}

SEC("kprobe/security_path_rename")
int BPF_KPROBE(kp_path_rename, struct path *old_dir,
	       struct dentry *old_dentry, struct path *new_dir,
	       struct dentry *new_dentry)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct vfsmount *old_mnt, *new_mnt;
	struct scratch *s;

	s = stage_begin(id);
	old_mnt = BPF_CORE_READ(old_dir, mnt);
	new_mnt = BPF_CORE_READ(new_dir, mnt);
	if (!s || !old_dentry || !new_dentry || !old_mnt || !new_mnt)
		return 0;
	walk_begin(s);
	/* Both walks share s->w.matched: a match on either side counts. */
	walk_path(s, new_dentry, new_mnt, s->rec.path, &s->rec.path_len,
		  &s->rec.path_truncated);
	walk_path(s, old_dentry, old_mnt, s->rec.old_path,
		  &s->rec.old_path_len, &s->rec.old_path_truncated);
	if (!LOAD(s->w.matched))
		return 0;
	fill_actor(&s->rec, KIND_FS_RENAME, id);
	fill_inode(&s->rec, BPF_CORE_READ(old_dentry, d_inode));
	stage_commit(s, id);
	return 0;
}

/* A write-open or a truncate of `file`, staged as WRITE. */
static __always_inline void stage_file_write(struct file *file)
{
	stage_one(KIND_FS_WRITE, BPF_CORE_READ(file, f_path.dentry),
		  BPF_CORE_READ(file, f_path.mnt), BPF_CORE_READ(file, f_inode));
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(kp_file_open, struct file *file)
{
	fmode_t fmode = BPF_CORE_READ(file, f_mode);
	struct inode *inode;
	struct fs_record *staged;
	__u64 id;

	/* The hot path: everything but a write-open of a regular file leaves
	 * here, before any map access. */
	if (!(fmode & FMODE_WRITE))
		return 0;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode || (BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFREG)
		return 0;

	id = bpf_get_current_pid_tgid();
	staged = bpf_map_lookup_elem(&PENDING, &id);
	if (!staged) {
		stage_file_write(file);
		return 0;
	}
	/* The CREATE staged by security_path_mknod in this open(O_CREAT):
	 * the same dentry, now with its inode. Anything else staged first
	 * stays as it is (first hook wins). */
	if (staged->hdr.kind == KIND_FS_CREATE && !staged->has_inode)
		fill_inode(staged, inode);
	return 0;
}

SEC("kprobe/security_path_truncate")
int BPF_KPROBE(kp_path_truncate, struct path *path)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);

	stage_one(KIND_FS_WRITE, dentry, BPF_CORE_READ(path, mnt),
		  BPF_CORE_READ(dentry, d_inode));
	return 0;
}

/* Linux 6.2+ only; its attach is optional. */
SEC("kprobe/security_file_truncate")
int BPF_KPROBE(kp_file_truncate, struct file *file)
{
	stage_file_write(file);
	return 0;
}

/* sys_enter_<sc>: forget anything staged outside this syscall. */
static __always_inline int on_enter(void)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&PENDING, &id);
	return 0;
}

/* sys_exit_<sc>: emit the staged operation if the syscall succeeded. */
static __always_inline int on_exit(long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fs_record *staged = bpf_map_lookup_elem(&PENDING, &id);
	struct fs_record *rec;

	if (!staged)
		return 0;
	if (ret >= 0) {
		rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);
		if (!rec) {
			count_drop();
		} else if (bpf_probe_read_kernel(rec, sizeof(*rec), staged) != 0) {
			bpf_ringbuf_discard(rec, 0);
			count_drop();
		} else {
			rec->ret = (__s32)ret;
			rec->ktime_ns = bpf_ktime_get_ns();
			bpf_ringbuf_submit(rec, 0);
		}
	}
	bpf_map_delete_elem(&PENDING, &id);
	return 0;
}

#define SYSCALL_PROGS(sc)                                                  \
	SEC("tp/syscalls/sys_enter_" #sc)                                  \
	int tp_enter_##sc(void *ctx)                                       \
	{                                                                  \
		return on_enter();                                         \
	}                                                                  \
	SEC("tp/syscalls/sys_exit_" #sc)                                   \
	int tp_exit_##sc(struct trace_event_raw_sys_exit *ctx)             \
	{                                                                  \
		return on_exit(ctx->ret);                                  \
	}

SYSCALL_PROGS(open)
SYSCALL_PROGS(openat)
SYSCALL_PROGS(openat2)
SYSCALL_PROGS(creat)
SYSCALL_PROGS(truncate)
SYSCALL_PROGS(ftruncate)
SYSCALL_PROGS(mknod)
SYSCALL_PROGS(mknodat)
SYSCALL_PROGS(mkdir)
SYSCALL_PROGS(mkdirat)
SYSCALL_PROGS(unlink)
SYSCALL_PROGS(unlinkat)
SYSCALL_PROGS(rmdir)
SYSCALL_PROGS(rename)
SYSCALL_PROGS(renameat)
SYSCALL_PROGS(renameat2)

/* A thread that exits mid-syscall (or never reaches an exit tracepoint)
 * leaves no entry behind. */
SEC("tp/sched/sched_process_exit")
int tp_task_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&PENDING, &id);
	return 0;
}
