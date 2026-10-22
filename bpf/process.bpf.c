// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * OSIRIS process exec/exit BPF program (CO-RE, built by tools/ebpf/build.sh,
 * loaded by the Rust `aya` loader in crates/osiris-ebpf).
 *
 * Emits fixed-size records (bpf/process.h) into the EVENTS ring buffer:
 *   handle_exec  tp/sched/sched_process_exec  -> struct exec_record
 *   handle_exit  tp/sched/sched_process_exit  -> struct exit_record
 *                                                (once, when the thread
 *                                                group dies)
 * Events from the tgid in SELF_TGID[0] (the agent itself) are skipped; 0
 * means "unset". A failed ring-buffer reservation increments DROPS[0].
 *
 * Verifier notes (target: Linux 5.15+, privileged load):
 *  - every reservation is a constant sizeof(record) and is submitted on
 *    every path after a successful reserve;
 *  - the argv read size is clamped to ARGS_MAX and re-checked after a
 *    compiler barrier so the exact register passed to the helper carries
 *    the bound;
 *  - no loops; all string/array reads use constant-size helpers.
 */
#include "vmlinux_min.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "process.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Record schema version, read from .rodata by the loader before load. */
const volatile __u32 schema_version = SCHEMA_VERSION;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
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

/*
 * signal_struct.flags bit set by every group exit: do_group_exit()
 * (exit_group(2) with or without other threads), complete_signal() for a
 * fatal signal, and the core-dump path. 0x00000004 in
 * include/linux/sched/signal.h on 5.15 (where SIGNAL_GROUP_COREDUMP 0x8
 * still exists beside it) and on every 6.x; the value is not exported in
 * BTF, so it is hard-coded.
 */
#define SIGNAL_GROUP_EXIT 0x00000004
#ifndef EEXIST
#define EEXIST 17
#endif

/* One thread group's identity: tgid plus the leader's start time. */
struct group_key {
	__u64 start_boottime_ns;
	__u32 tgid;
	__u32 _pad;
};

/*
 * Groups whose exit record was already emitted. Several threads can see
 * signal->live == 0 (see handle_exit), and only the first to insert the
 * key emits. Keys are never deleted: the start time makes a reused tgid a
 * new key, and LRU recycling of 4096 keys only has to outlive the short
 * window between those threads' tracepoints.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct group_key);
	__type(value, __u8);
} EXITED SEC(".maps");

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

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct task_struct *task;
	struct mm_struct *mm;
	struct inode *exe_inode = 0;
	struct exec_record *rec;
	__u64 uid_gid, arg_start = 0, arg_end = 0, len = 0;
	__u32 fname_off;
	long n;

	if (is_self(tgid))
		return 0;

	rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);
	if (!rec) {
		count_drop();
		return 0;
	}

	/*
	 * Ring-buffer memory is not zeroed. Every scalar field is written
	 * below; the filename/args tails beyond filename_len/args_len may hold
	 * bytes of earlier records and the consumer only reads up to the
	 * stated lengths.
	 */
	task = (struct task_struct *)bpf_get_current_task();
	uid_gid = bpf_get_current_uid_gid();

	rec->hdr.schema_version = SCHEMA_VERSION;
	rec->hdr.kind = KIND_EXEC;
	rec->pid = tgid;
	rec->ppid = BPF_CORE_READ(task, real_parent, tgid);
	rec->uid = (__u32)uid_gid;
	rec->gid = (__u32)(uid_gid >> 32);
	rec->ktime_ns = bpf_ktime_get_ns();
	rec->start_boottime_ns = BPF_CORE_READ(task, start_boottime);
	bpf_get_current_comm(rec->comm, sizeof(rec->comm));
	rec->args_truncated = 0;
	__builtin_memset(rec->_pad, 0, sizeof(rec->_pad));

	/* __data_loc: low 16 bits are the string's offset within the record. */
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	n = bpf_probe_read_kernel_str(rec->filename, sizeof(rec->filename),
				      (void *)ctx + fname_off);
	if (n > 0) {
		rec->filename_len = (__u32)(n - 1);
	} else {
		rec->filename_len = 0;
		rec->filename[0] = '\0';
	}

	/*
	 * argv lives in the new image's user memory: [arg_start, arg_end).
	 * The image's identity is mm->exe_file's inode: begin_new_exec() has
	 * already installed bprm->file as the new mm's exe_file when this
	 * tracepoint fires (exec_binprm(), after the binfmt loader), on 5.15
	 * and 6.x alike. s_dev is the kernel dev_t; user space converts it to
	 * st_dev. A failed read leaves 0 = unknown.
	 */
	rec->exe_dev = 0;
	rec->exe_ino = 0;
	mm = BPF_CORE_READ(task, mm);
	if (mm) {
		arg_start = BPF_CORE_READ(mm, arg_start);
		arg_end = BPF_CORE_READ(mm, arg_end);
		exe_inode = BPF_CORE_READ(mm, exe_file, f_inode);
	}
	if (exe_inode) {
		rec->exe_ino = BPF_CORE_READ(exe_inode, i_ino);
		rec->exe_dev = BPF_CORE_READ(exe_inode, i_sb, s_dev);
	}
	if (arg_end > arg_start)
		len = arg_end - arg_start;
	if (len > ARGS_MAX) {
		len = ARGS_MAX;
		rec->args_truncated = 1;
	}
	rec->args_len = 0;
	/*
	 * Barrier: stop clang from folding the clamp above into the check
	 * below (e.g. into a `len - 1 < N` range test on another register),
	 * so the verifier sees `len <= ARGS_MAX` on the very register passed
	 * as the helper's size. Zero is a valid size for this helper.
	 */
	asm volatile("" : "+r"(len));
	if (len <= ARGS_MAX &&
	    bpf_probe_read_user(rec->args, len, (const void *)arg_start) == 0)
		rec->args_len = (__u32)len;

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task, *leader;
	struct signal_struct *sig;
	struct group_key key;
	struct exit_record *rec;
	__u32 status;
	__u8 one = 1;

	if (is_self(tgid))
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	sig = BPF_CORE_READ(task, signal);
	if (!sig)
		return 0;

	/*
	 * The process ends when its thread group dies, not when the leader
	 * exits: a leader's pthread_exit() leaves the group running, and a
	 * non-leader's execve() kills the old leader (de_thread) while the
	 * process lives on. do_exit() on 5.15 and 6.x runs, in order:
	 *
	 *   group_dead = atomic_dec_and_test(&tsk->signal->live);
	 *   ... tsk->exit_code = code; ... exit_mm(); ...
	 *   trace_sched_process_exit(tsk);
	 *
	 * so every exiting thread has already decremented signal->live here
	 * and a non-zero value means other threads are still running. More
	 * than one thread can read 0 (A decrements to 1, B to 0, then both
	 * reach the tracepoint), so EXITED lets only the first emit.
	 * signal_struct is freed only after the last thread is released, so
	 * it is valid here. exit_mm() has cleared current->mm, which is why
	 * exit records carry no exe identity.
	 */
	if (BPF_CORE_READ(sig, live.counter) != 0)
		return 0;

	/* The leader stays allocated (a zombie at worst) until the group is
	 * empty, so its start time and comm are readable: they key the exit
	 * to the exec's process_key. */
	leader = BPF_CORE_READ(task, group_leader);
	key.start_boottime_ns = BPF_CORE_READ(leader, start_boottime);
	key.tgid = tgid;
	key._pad = 0;
	if (bpf_map_update_elem(&EXITED, &key, &one, BPF_NOEXIST) == -EEXIST)
		return 0;

	/*
	 * The status a waiting parent's wait() sees (wait_task_zombie() on
	 * 5.15 and 6.x): signal->group_exit_code when SIGNAL_GROUP_EXIT is set
	 * (exit_group(), a fatal signal, a core dump; the core flag 0x80 is
	 * already or'd in), else the last thread's own exit_code (every
	 * thread ended by pthread_exit(); also a single-threaded
	 * exit_group() on 5.15, whose do_group_exit() skips the flag and
	 * passes the same code to do_exit()).
	 */
	if (BPF_CORE_READ(sig, flags) & SIGNAL_GROUP_EXIT)
		status = (__u32)BPF_CORE_READ(sig, group_exit_code);
	else
		status = (__u32)BPF_CORE_READ(task, exit_code);

	rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);
	if (!rec) {
		count_drop();
		return 0;
	}

	rec->hdr.schema_version = SCHEMA_VERSION;
	rec->hdr.kind = KIND_EXIT;
	rec->pid = tgid;
	rec->ppid = BPF_CORE_READ(leader, real_parent, tgid);
	rec->uid = (__u32)bpf_get_current_uid_gid();
	rec->exit_status = status;
	rec->ktime_ns = bpf_ktime_get_ns();
	rec->start_boottime_ns = key.start_boottime_ns;
	/* The leader's comm, as v1 reported (the last thread may be a named
	 * worker thread); zero-filled by the helper if the read fails. */
	BPF_CORE_READ_STR_INTO(&rec->comm, leader, comm);

	bpf_ringbuf_submit(rec, 0);
	return 0;
}
