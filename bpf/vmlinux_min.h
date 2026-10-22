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
/* Kernel-internal dev_t: MAJOR = dev >> 20, MINOR = dev & 0xfffff. */
typedef __u32 dev_t;

/* include/linux/types.h; the kernel's BTF has the same anonymous struct. */
typedef struct {
	int counter;
} __attribute__((preserve_access_index)) atomic_t;

/* Subset of enum bpf_map_type (include/uapi/linux/bpf.h); values are ABI. */
enum bpf_map_type {
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

struct super_block {
	dev_t s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
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
	char comm[16];
	/* Boot-based start time in ns; present since Linux 5.5. */
	u64 start_boottime;
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

#endif /* OSIRIS_VMLINUX_MIN_H */
