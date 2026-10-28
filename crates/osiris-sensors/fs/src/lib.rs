pub mod assembler;
pub mod audit_record;
pub mod ebpf_backend;
pub mod exe_index;
pub mod sensor;
pub mod watch;

pub use assembler::{group_to_file_events, AuditEventAssembler};
pub use audit_record::{
    parse_record, AuditRecord, NameType, PathRecord, SyscallClass, SyscallRecord,
};
pub use ebpf_backend::{fs_to_raw, fs_to_raw_indexed};
pub use exe_index::ExeIndex;
pub use sensor::FilesystemSensor;
pub use watch::{resolve_watch_paths, watch_key, WatchKey, WatchResolution, DEFAULT_WATCH_PATHS};
