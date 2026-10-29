# ADR-010: eBPF user-space loader is aya; kernel programs stay clang-built C CO-RE

Status: accepted, 2026-10-18 (Phase 11b-1). Supersedes the loader choice in ARCHITECTURE.md
§5.2 (libbpf-rs). Spec: `docs/superpowers/specs/2026-10-18-phase-11b1-ebpf-process-design.md`.

## Context

ARCHITECTURE §5.2 chose libbpf-rs for the loader and C compiled by clang for the kernel
programs, and said Aya could be reconsidered through an ADR. Phase 11b-1 builds the first
eBPF engine (`crates/osiris-ebpf`) and the exec/exit backend of the `process_exec` sensor.
`libbpf-rs` depends on `libbpf-sys`, which builds libbpf, libelf and zlib from C. That cannot be
built or type-checked on the Windows development host, and it puts a C toolchain into every
Linux cargo build. §5.4 also asked for the Rust record struct to be generated from one source,
and the BPF programs to see kernel structs through a generated `vmlinux.h`.

## Decision

1. **Loader: aya 0.14.0, pinned exactly**, under `[target.'cfg(target_os = "linux")'.dependencies]`
   only. aya loads clang-built, BTF-carrying CO-RE objects and applies the relocations itself.
   All cargo builds stay pure Rust, and the Linux-only code is cross-checked from Windows with
   `--target x86_64-unknown-linux-gnu`.
2. **Kernel programs stay restricted C, compiled by clang** (`-target bpf -g -O2`), exactly as
   §5.2 says. Only the loader changed.
3. **The object is built outside cargo.** `tools/ebpf/build.sh` compiles `bpf/process.bpf.c` and
   writes `process.bpf.o` plus `process.bpf.o.sha256`. Nothing compiled is committed. The agent
   loads the object at run time from `ebpf.object_dir` and checks the SHA-256 sidecar first.
   Cargo builds and tests never need clang, root or BTF. Building the object needs clang and
   `libbpf-dev` (BPF helper headers) on the build host.
4. **Record layout by mirror plus tests, not codegen.** `bpf/process.h` defines the records
   (with `_Static_assert`s on size and offsets). A hand-written `#[repr(C)]` Rust struct mirrors
   it, with unit tests pinning size and field offsets. Every record starts with
   `{ schema_version, kind }`. The loader reads the object's `.rodata` schema version with its own
   bounded ELF reader and refuses a mismatch with a typed error. This replaces §5.4's build-time
   codegen.
5. **Minimal hand-declared CO-RE structs** (`bpf/vmlinux_min.h`, `preserve_access_index`) instead
   of a generated multi-megabyte `vmlinux.h`.

## Consequences

- Windows development and the existing CI need no C toolchain; the Linux code is checked by
  cross-`clippy`, and behaviour is proven on real kernels.
- The loader is a pure-Rust dependency tree (aya and its crates) that we pin; upgrades are
  deliberate.
- The object must be shipped and found at run time; a missing, corrupted or incompatible object
  is a visible fallback to the audit backend (health DEGRADED, flag `audit_fallback`), never a
  silent no-op. Packaging the object is Phase 13.
- The C/Rust layout agreement rests on tests and the schema-version check, not generation.
  Adding a field means editing the C header, the Rust mirror and the version constant together;
  forgetting one fails the layout tests or the load, not the kernel read.
- Validation: GitHub Actions run 39139529617 (commit `e5becff`, branch `real-linux/t11b1-1`)
  passed on ubuntu-22.04 and ubuntu-24.04 on the first run (kernel versions as reported then: 5.15 and 6.x; not recorded by the run).

## Cost if wrong, and revisit triggers

| Decision | Cost if wrong | Revisit when |
|---|---|---|
| aya instead of libbpf-rs | Moderate: loader code in `crates/osiris-ebpf` is small and isolated behind the engine API; programs are unchanged C, so switching to libbpf-rs rewrites only the loader. | aya cannot load a program type 11b-2..4 needs (LSM, uprobe on resolver libraries, cgroup hooks), or its verifier/relocation behaviour breaks on a target kernel, or the project stops being maintained. |
| Object built outside cargo, loaded at run time | Low: a packaging concern. A mismatch is caught by the digest and schema checks. | Phase 13 packaging, or if operators cannot reliably deploy the object next to the binary (embed it with `include_bytes!` then). |
| Hand-mirrored record + layout tests + schema check | Medium: a mismatch that tests miss is a memory-safety bug in decoding. Mitigated by static asserts, offset tests and the version check. | The number of record types grows (11b-2 network, 11b-3 filesystem) enough that hand-mirroring becomes error-prone: add codegen from one source as §5.4 asks. |
| Minimal CO-RE structs instead of `vmlinux.h` | Low: a field missing from the minimal header is a compile error, not a runtime one. | Programs need many more kernel structs (network, filesystem), at which point a generated BTF header may be cheaper. |
| Kernel-version coverage = the two runner kernels | Medium: untested on RHEL-like or older kernels (the ring buffer needs >= 5.8). | Before claiming support for other distros: add the VM matrix of §26. |

## Update (Phase 11b-2): one object per sensor

Phase 11b-2 generalises the loader and adds a second object, so there is now one BPF object per
sensor: `process.bpf.o` (schema 2) and `net.bpf.o` (schema 1), each with its own `.sha256`
sidecar and `.rodata` `schema_version`, both in `ebpf.object_dir`. The record layouts are still
mirrored by hand (C header, `#[repr(C)]` struct, offset tests, version check); the net record
makes the count of hand-mirrored records three, and the codegen revisit trigger above stays open.
Process record v2 adds the exec'd image identity (`exe_dev`, `exe_ino`) in what was padding.
`aya` stays at 0.14.0. Kernel-side details worth recording:

- `process.bpf.c` keeps an `EXITED` dedup map (`LRU_HASH`, 4096 entries, key
  `{start_boottime, tgid}`), so two threads that both see `signal->live == 0` emit one group exit.
- When all threads call `pthread_exit`, the reported exit status is that of the first thread to
  observe `live == 0`, not necessarily the leader's.
- The net socket-owner map (`SOCKS`) is an LRU of 65 536 entries whose per-CPU free lists can evict
  before it is full. The accept-time insert versus peer-close race is not fenced, so a stale
  entry can stay until the next connect/accept at that socket address overwrites it or it is
  evicted. A socket that reaches CLOSE without a connect/accept (a passive child reset before
  `accept()`, an io_uring or in-kernel accept) meanwhile is reported under the stale owner: at
  worst one later CLOSE at a reused socket address may be attributed to the wrong pid.
- Net records carry the owner's thread-group leader comm (as `/proc/<pid>/comm` and the exit
  record do), not the calling thread's.
- Validation: GitHub Actions run 40039969622 (commit `8e4d8d6`, branch `real-linux/t11b2-1`)
  passed on ubuntu-22.04 and ubuntu-24.04 on the first push. The post-review re-run 40043542332
  (commit `6140b74`) passed on kernels `6.8.0-1064-azure` (ubuntu-22.04) and `6.17.0-1022-azure`
  (ubuntu-24.04). No 5.15 kernel was run, so the 5.15 floor is reasoned (CO-RE).

## Update (Phase 11b-3): filesystem object, kprobes, optional attach points

Phase 11b-3 adds a third object, `fs.bpf.o` (schema 1), and the loader gains what it needs. `aya`
stays at 0.14.0. Validation runs are listed in `docs/VALIDATION.md`.

- **Kprobes on the LSM path hooks, not BPF-LSM and not fentry.** The hooks are
  `security_path_mknod`, `security_path_mkdir`, `security_path_unlink`, `security_path_rmdir`,
  `security_path_rename`, `security_file_open`, `security_path_truncate` and
  `security_file_truncate`. BPF-LSM needs `lsm=...,bpf` on the kernel command line, which stock
  Ubuntu, Debian and RHEL do not set, so the runners could never exercise it. fentry on arm64
  needs 6.0+. The `security_path_*` signatures have been stable since well before 5.15. `ObjectSpec`
  gained a kprobe list and the loader attaches them with aya's `KProbe`.
- **Optional attach points.** Every tracepoint or kprobe entry has a `required` flag. A missing
  optional one (`security_file_truncate` before kernel 6.2, a legacy syscall tracepoint absent on
  some architectures) is skipped and listed in the load report. A missing required one fails the
  load with a reason naming it, and the sensor falls back to audit. The process and net specs keep
  all entries required. The optional path is covered by a loader unit test (a spec naming a
  nonexistent symbol as optional); it is not exercised on the runners, whose kernels are all 6.2 or
  later.
- **Stage at the hook, emit at syscall exit.** A path hook fires before the operation can fail, so
  it only stages the operation in a `PENDING` hash (keyed by `pid_tgid`, `BPF_F_NO_PREALLOC`,
  10 240 entries). A per-syscall `sys_exit_*` tracepoint emits it when the return value is not
  negative. `sys_enter_*` clears the thread's entry so a stale one (io_uring, a thread that died
  mid-syscall) is never emitted at an unrelated exit.
- **Verifier approach.** The first design unrolled the ancestor walk 32 times; the verifier
  rejected it as "BPF program is too large" (over 1M instructions; GitHub Actions run
  40432835805). The accepted design is a bounded, non-unrolled loop (kernel 5.3+, no `bpf_loop`)
  with all loop-carried state kept in a per-CPU scratch map through volatile loads and stores, and
  every function `__always_inline` (no BPF-to-BPF calls). It loaded and attached on both runner
  kernels (run 40768725486).
- **Final `PATH_CAP` is 1024 bytes, unchanged**, and `MAX_COMPONENTS` is 32, unchanged: the bounded
  loop made shrinking the buffer unnecessary. A path that does not fit is rendered as a truncated
  tail with a `…/` prefix; the walk keeps testing ancestors against `WATCH` after the buffer is
  full, so truncation never causes a miss (run 40771969598). The ring buffer is 4 MiB (records are
  about 2 KiB).
- **Known evasion: more than 32 components.** A file nested deeper than 32 levels (mount crossings
  count) below its watched directory is never matched, because the walk gives up before reaching
  the watched ancestor. It was accepted for the verifier budget. A later phase could add a cheaper
  match-only continuation past 32 components that builds no path.
- **x86_64 only.** Kprobe argument access is architecture-specific and the object is built with
  `-D__TARGET_ARCH_x86`; elsewhere the probe reports it and the sensor falls back. Per-arch objects
  are Phase 13 packaging work.
- **Layout re-evaluation: hand-mirrored layouts kept.** The 11b-1 debt asked whether codegen should
  replace the hand mirror once the third record existed. Decision: keep the mirror. `fs_record.rs`
  follows `net_record.rs`: `_Static_assert`s on the C side, `#[repr(C)]` plus size and offset
  tests on the Rust side, a test that reads the C header text and compares it with the Rust
  constants (`tests/c_header.rs`), the `schema_version` check at load, and a decoder that returns
  a `DecodeError` for any malformed record (bad kind, `path_len > PATH_CAP`, wrong size). That
  combination caught every layout mistake during the phase, and a mismatch cannot reach the
  kernel read unnoticed. Codegen (bindgen or a generator) would make a C toolchain a build
  requirement of the Rust workspace, which the first Consequence above rules out for Windows
  development and the existing CI. Revisit if a fourth sensor record is added or a layout test
  misses a real mismatch.
- **Debts this adds** (also in `docs/ROADMAP-REMAINING.md`): io_uring and compat file operations,
  no link/symlink/chmod/chown, no watch re-resolution, no container mount-namespace translation,
  inode-only matching on btrfs/overlayfs, 64 watch keys (more makes the whole sensor fall back
  instead of capping), the `exe_path` fallback index not working on btrfs/overlayfs, `PENDING`
  overflow.
