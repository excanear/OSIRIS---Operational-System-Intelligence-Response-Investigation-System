//! Shared eBPF engine for OSIRIS sensors.
//!
//! OS-neutral pieces: the `#[repr(C)]` record ABIs shared with the C BPF
//! programs (`record` for process, `net_record` for TCP), BPF object
//! integrity checking (`integrity`), the kernel exe identity and `exe_path`
//! resolver (`exe`), the capability probe's parsing and kernel-symbol check
//! (`probe`), the object specs (tracepoint and kprobe attach points, some
//! optional) and schema lookup (`loader`) and the kernel-clock offset
//! (`clock`).
//! Loading, attaching and ring-buffer reading use `aya` and are Linux-only;
//! off Linux `probe` reports unsupported and [`LoadedObject::load`] always
//! fails. It must not depend on `osiris-sensor-api`.

pub mod clock;
pub mod exe;
pub mod integrity;
pub mod loader;
pub mod net_record;
pub mod probe;
pub mod reader;
pub mod record;

pub use clock::boot_wall_offset_ns;
pub use exe::{dev_from_user, dev_to_user, resolve_exe, ExeIdentity};
pub use integrity::{verify_object, IntegrityError};
pub use loader::{
    object_schema_version, sidecar_name, AttachKind, AttachPoint, DropCounter, EbpfSettings,
    LoadError, LoadedObject, ObjectSpec, NET_OBJECT, PROCESS_OBJECT,
};
pub use net_record::{
    decode_net, NetEvent, NetKind, NetRecord, AF_INET, AF_INET6, DIR_INBOUND, DIR_OUTBOUND,
    KIND_NET_ACCEPT, KIND_NET_CLOSE, KIND_NET_CONNECT, NET_SCHEMA_VERSION,
};
pub use probe::{
    caps_allow_bpf, kernel_symbols_text, missing_kernel_symbols, parse_kernel_release, probe,
    ProbeReport,
};
pub use reader::{spawn_reader, ReaderError};
pub use record::{
    decode, decode_wait_status, DecodeError, ExecEvent, ExecRecord, ExitEvent, ExitRecord, Record,
    RecordHeader, ARGS_MAX, COMM_LEN, FILENAME_MAX, KIND_EXEC, KIND_EXIT, PROCESS_SCHEMA_VERSION,
};
