//! The C header `bpf/process.h` mirrors the Rust record ABI in `record.rs`.
//! Clang is not available to cargo, so this test checks the header text for
//! the constants and the `_Static_assert` sizes/offsets; the C compiler then
//! enforces those asserts when `tools/ebpf/build.sh` builds the object.

use std::mem::{offset_of, size_of};
use std::path::Path;

use osiris_ebpf::{
    ExecRecord, ExitRecord, ARGS_MAX, COMM_LEN, FILENAME_MAX, KIND_EXEC, KIND_EXIT,
    PROCESS_SCHEMA_VERSION,
};

fn header() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bpf/process.h");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn c_header_matches_rust_constants() {
    let h = header();
    let expected = [
        format!("#define SCHEMA_VERSION {PROCESS_SCHEMA_VERSION}"),
        format!("#define KIND_EXEC {KIND_EXEC}"),
        format!("#define KIND_EXIT {KIND_EXIT}"),
        format!("#define ARGS_MAX {ARGS_MAX}"),
        format!("#define FILENAME_MAX {FILENAME_MAX}"),
        format!("#define COMM_LEN {COMM_LEN}"),
        format!(
            "_Static_assert(sizeof(struct exec_record) == {},",
            size_of::<ExecRecord>()
        ),
        format!(
            "_Static_assert(sizeof(struct exit_record) == {},",
            size_of::<ExitRecord>()
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, comm) == {},",
            offset_of!(ExecRecord, comm)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, exe_dev) == {},",
            offset_of!(ExecRecord, exe_dev)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, exe_ino) == {},",
            offset_of!(ExecRecord, exe_ino)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, filename) == {},",
            offset_of!(ExecRecord, filename)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exec_record, args) == {},",
            offset_of!(ExecRecord, args)
        ),
        format!(
            "_Static_assert(__builtin_offsetof(struct exit_record, comm) == {},",
            offset_of!(ExitRecord, comm)
        ),
    ];
    for line in &expected {
        assert!(h.contains(line.as_str()), "bpf/process.h lacks `{line}`");
    }
    // Pinned values from the brief, independent of the Rust constants.
    assert!(h.contains("#define SCHEMA_VERSION 2"));
    assert!(h.contains("_Static_assert(sizeof(struct exec_record) == 4432,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, exe_dev) == 68,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, exe_ino) == 72,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, filename) == 80,"));
    assert!(h.contains("_Static_assert(__builtin_offsetof(struct exec_record, args) == 336,"));
    assert!(h.contains("_Static_assert(sizeof(struct exit_record) == 56,"));
}
