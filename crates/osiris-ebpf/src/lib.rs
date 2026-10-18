//! Shared eBPF engine for OSIRIS sensors.
//!
//! OS-neutral pieces: the `#[repr(C)]` record ABI shared with the C BPF
//! program (`record`), BPF object integrity checking (`integrity`), the
//! capability probe's parsing (`probe`) and the object's schema lookup
//! (`loader`). Loading, attaching and ring-buffer reading use `aya` and are
//! Linux-only; off Linux `probe` reports unsupported and
//! [`ProcessProgram::load`] always fails. It must not depend on
//! `osiris-sensor-api`.

pub mod integrity;
pub mod loader;
pub mod probe;
pub mod reader;
pub mod record;

pub use integrity::{verify_object, IntegrityError};
pub use loader::{object_schema_version, DropCounter, LoadError, ProcessProgram};
pub use probe::{caps_allow_bpf, parse_kernel_release, probe, ProbeReport};
pub use reader::{spawn_reader, ReaderError};
pub use record::{
    decode, decode_wait_status, DecodeError, ExecEvent, ExecRecord, ExitEvent, ExitRecord, Record,
    RecordHeader, ARGS_MAX, COMM_LEN, FILENAME_MAX, KIND_EXEC, KIND_EXIT, SCHEMA_VERSION,
};
