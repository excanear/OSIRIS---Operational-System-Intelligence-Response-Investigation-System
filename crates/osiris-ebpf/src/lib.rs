//! Shared eBPF engine for OSIRIS sensors.
//!
//! This crate holds the OS-neutral pieces: the `#[repr(C)]` record ABI shared
//! with the C BPF program (`record`) and BPF object integrity checking
//! (`integrity`). Linux-only `probe`, `loader` and `reader` modules are added
//! alongside these in later tasks. It must not depend on `osiris-sensor-api`.

pub mod integrity;
pub mod record;

pub use integrity::{verify_object, IntegrityError};
pub use record::{
    decode, decode_wait_status, DecodeError, ExecEvent, ExecRecord, ExitEvent, ExitRecord, Record,
    RecordHeader, ARGS_MAX, COMM_LEN, FILENAME_MAX, KIND_EXEC, KIND_EXIT, SCHEMA_VERSION,
};
