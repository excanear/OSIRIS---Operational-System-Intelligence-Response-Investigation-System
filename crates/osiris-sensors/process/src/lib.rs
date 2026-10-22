pub mod assembler;
pub mod audit_line;
pub mod ebpf_backend;
pub mod execve;
pub mod proc_stat;
pub mod sensor;

pub use assembler::ExecAssembler;
pub use audit_line::parse_audit_line;
pub use ebpf_backend::{exec_to_raw, exit_to_raw, split_argv};
/// Lives in `osiris-ebpf` (shared with the network sensor); re-exported so
/// callers keep `osiris_sensors_process::EbpfSettings`.
pub use osiris_ebpf::EbpfSettings;
pub use proc_stat::{parse_proc_stat_starttime, read_process_start_time};
pub use sensor::ProcessExecSensor;
