use serde::{Deserialize, Serialize};

/// Where a raw record originated — carried through to CanonicalEvent.source
/// during normalization (ARCHITECTURE.md §9.2's `source` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEventSource {
    Audit,
    Synthetic,
}

/// A Process/Exec creation record at MINIMAL telemetry (ARCHITECTURE.md §6:
/// "create/exit, pid/ppid/uid/exe" — no argv/env at this level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the originating backend.
    pub timestamp_ns: u64,
    /// Best-effort process start time for process_key hashing
    /// (ARCHITECTURE.md §9.2). Falls back to `timestamp_ns` when the real
    /// monotonic start time (e.g. /proc/<pid>/stat's starttime) isn't
    /// available.
    pub start_time_mono: u64,
    pub source: RawEventSource,
}

/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scopes this to Process/Exec only; later
/// phases add File/Network/Dns/... variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
}
