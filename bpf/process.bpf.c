// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * OSIRIS process exec/exit BPF program (CO-RE, built by tools/ebpf/build.sh,
 * loaded by the Rust `aya` loader in crates/osiris-ebpf).
 *
 * Emits fixed-size records (bpf/process.h) into the EVENTS ring buffer:
 *   handle_exec  tp/sched/sched_process_exec  -> struct exec_record
 *   handle_exit  tp/sched/sched_process_exit  -> struct exit_record
 *                                                (thread-group leaders only)
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

	/* argv lives in the new image's user memory: [arg_start, arg_end). */
	mm = BPF_CORE_READ(task, mm);
	if (mm) {
		arg_start = BPF_CORE_READ(mm, arg_start);
		arg_end = BPF_CORE_READ(mm, arg_end);
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
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 pid = (__u32)pid_tgid;
	struct task_struct *task;
	struct exit_record *rec;

	/* Only the thread-group leader's exit ends the process. */
	if (pid != tgid)
		return 0;
	if (is_self(tgid))
		return 0;

	rec = bpf_ringbuf_reserve(&EVENTS, sizeof(*rec), 0);
	if (!rec) {
		count_drop();
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();

	rec->hdr.schema_version = SCHEMA_VERSION;
	rec->hdr.kind = KIND_EXIT;
	rec->pid = tgid;
	rec->ppid = BPF_CORE_READ(task, real_parent, tgid);
	rec->uid = (__u32)bpf_get_current_uid_gid();
	/* do_exit() stores the wait status in exit_code before this point. */
	rec->exit_status = (__u32)BPF_CORE_READ(task, exit_code);
	rec->ktime_ns = bpf_ktime_get_ns();
	rec->start_boottime_ns = BPF_CORE_READ(task, start_boottime);
	bpf_get_current_comm(rec->comm, sizeof(rec->comm));

	bpf_ringbuf_submit(rec, 0);
	return 0;
}
