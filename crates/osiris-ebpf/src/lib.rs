//! Shared eBPF engine for OSIRIS sensors.
//!
//! OS-neutral pieces: the `#[repr(C)]` record ABI shared with the C BPF
//! programs (`record`), BPF object integrity checking (`integrity`), the
//! capability probe's parsing (`probe`), the object specs and schema lookup
//! (`loader`) and the kernel-clock offset (`clock`). Loading, attaching and
//! ring-buffer reading use `aya` and are Linux-only; off Linux `probe`
//! reports unsupported and [`LoadedObject::load`] always fails. It must not
//! depend on `osiris-sensor-api`.

pub mod clock;
pub mod exe;
pub mod integrity;
pub mod loader;
pub mod probe;
pub mod reader;
pub mod record;

pub use clock::boot_wall_offset_ns;
pub use exe::{dev_to_user, resolve_exe, ExeIdentity};
pub use integrity::{verify_object, IntegrityError};
pub use loader::{
    object_schema_version, sidecar_name, DropCounter, EbpfSettings, LoadError, LoadedObject,
    ObjectSpec, PROCESS_OBJECT,
};
pub use probe::{caps_allow_bpf, parse_kernel_release, probe, ProbeReport};
pub use reader::{spawn_reader, ReaderError};
pub use record::{
    decode, decode_wait_status, DecodeError, ExecEvent, ExecRecord, ExitEvent, ExitRecord, Record,
    RecordHeader, ARGS_MAX, COMM_LEN, FILENAME_MAX, KIND_EXEC, KIND_EXIT, PROCESS_SCHEMA_VERSION,
};
