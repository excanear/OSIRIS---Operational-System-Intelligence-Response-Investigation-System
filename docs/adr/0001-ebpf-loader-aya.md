# ADR 0001: eBPF user-space loader is aya; kernel programs stay clang-built C CO-RE

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
  passed on ubuntu-22.04 (kernel 5.15) and ubuntu-24.04 (6.x) on the first run.

## Cost if wrong, and revisit triggers

| Decision | Cost if wrong | Revisit when |
|---|---|---|
| aya instead of libbpf-rs | Moderate: loader code in `crates/osiris-ebpf` is small and isolated behind the engine API; programs are unchanged C, so switching to libbpf-rs rewrites only the loader. | aya cannot load a program type 11b-2..4 needs (LSM, uprobe on resolver libraries, cgroup hooks), or its verifier/relocation behaviour breaks on a target kernel, or the project stops being maintained. |
| Object built outside cargo, loaded at run time | Low: a packaging concern. A mismatch is caught by the digest and schema checks. | Phase 13 packaging, or if operators cannot reliably deploy the object next to the binary (embed it with `include_bytes!` then). |
| Hand-mirrored record + layout tests + schema check | Medium: a mismatch that tests miss is a memory-safety bug in decoding. Mitigated by static asserts, offset tests and the version check. | The number of record types grows (11b-2 network, 11b-3 filesystem) enough that hand-mirroring becomes error-prone: add codegen from one source as §5.4 asks. |
| Minimal CO-RE structs instead of `vmlinux.h` | Low: a field missing from the minimal header is a compile error, not a runtime one. | Programs need many more kernel structs (network, filesystem), at which point a generated BTF header may be cheaper. |
| Kernel-version coverage = the two runner kernels | Medium: untested on RHEL-like or older kernels (the ring buffer needs >= 5.8). | Before claiming support for other distros: add the VM matrix of §26. |
