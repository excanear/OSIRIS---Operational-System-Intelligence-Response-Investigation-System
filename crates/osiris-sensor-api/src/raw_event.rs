use serde::{Deserialize, Serialize};

/// Where a raw record originated — carried through to CanonicalEvent.source
/// during normalization (ARCHITECTURE.md §9.2's `source` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEventSource {
    Audit,
    Synthetic,
    /// Sampled from `/proc` (e.g. `/proc/net/tcp` polling), not from Linux
    /// audit — carries no audit serial and no guarantee of catching every
    /// transition between poll ticks.
    Procfs,
    /// Queried from a container runtime's API (Docker/containerd/CRI-O over
    /// its unix socket). Not used by any sensor yet this phase (Phase 5
    /// plan Global Constraint #1: the Container sensor ships its
    /// cgroup-only fallback first, which honestly reports
    /// `RawEventSource::Procfs`) — added now so the deferred primary
    /// backend is a value change, not a type change, when implemented.
    ContainerApi,
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

/// The four filesystem operations this phase emits — ARCHITECTURE.md §6's
/// Filesystem STANDARD row ("create/delete/rename on watched paths") plus
/// write, which the audit backend yields from the same PATH records. No
/// read, permission, owner, or attribute operations: those are §6's
/// DETAILED/FORENSIC rungs (Phase 2 plan Global Constraints #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Write,
    Delete,
    Rename,
}

/// A filesystem operation record. Unlike `ProcessExecRaw` this is assembled
/// from *several* correlated audit records (one `type=SYSCALL` supplying the
/// acting process fields, one `type=PATH` supplying the file fields, and
/// optionally one `type=CWD` used to absolutize a relative path), so every
/// field here is already joined and absolute by the time a sensor emits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventRaw {
    pub operation: FileOperation,
    /// Absolute path. For `Rename` this is the *destination* path.
    ///
    /// KNOWN LIMITATION (audit backend): a relative `name=` from a `*at()`
    /// syscall (`openat`, `unlinkat`, `renameat`, ...) called with a real
    /// (non-`AT_FDCWD`) dirfd is resolved against the group's process-CWD
    /// record, not the directory the dirfd actually named — audit's
    /// `type=PATH` records don't carry enough information to recover that
    /// directory. This can produce a confidently absolute but wrong path
    /// (see `osiris_sensors_fs::assembler::absolutize`'s doc comment). The
    /// `inode`/`device_id` identity below is unaffected, so identity-based
    /// joins (File Story) remain correct even when `path` isn't.
    pub path: String,
    /// Only set for `Rename`: the source path the file moved from.
    pub previous_path: Option<String>,
    /// Inode and device of the file itself. `None` when the backend could
    /// not report them (an audit PATH record omits them for some
    /// `nametype=UNKNOWN` items) — the pipeline then emits no entity-graph
    /// edge rather than inventing an identity.
    pub inode: Option<u64>,
    /// See `osiris_schema::encode_device_id` for the encoding.
    pub device_id: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    /// The acting process, from the group's `type=SYSCALL` record.
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the audit event header.
    pub timestamp_ns: u64,
    /// The originating audit event's serial, retained for provenance so an
    /// operator can find the exact record group in the source log.
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// The three connection lifecycle events this phase emits — ARCHITECTURE.md
/// §6's Network STANDARD row ("connect/accept/close, 5-tuple"). No
/// SOCKET_CREATE/BIND/LISTEN this phase (Phase 3 plan Global Constraints
/// #3) — a listening socket's own lifecycle needs finer-grained state
/// tracking than one poll-interval diff reliably distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkOperation {
    Connect,
    Accept,
    Close,
}

/// Which side of the connection this host is. Derived from a documented
/// port-range heuristic, not ground truth (Phase 3 plan Global Constraints
/// #4) — `/proc/net/tcp` alone does not report which side initiated a
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

/// A TCP connection lifecycle record, assembled from a `/proc/net/tcp`
/// snapshot diff plus a best-effort `/proc/<pid>/fd` inode scan for process
/// attribution (Phase 3 plan Global Constraints #1/#5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventRaw {
    pub operation: NetworkOperation,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Always `"tcp"` this phase (IPv4-only, Global Constraints #1/#2) —
    /// kept as a string rather than an enum so a later UDP/IPv6 backend
    /// extends this field's value set without a breaking type change.
    pub proto: String,
    pub direction: NetworkDirection,
    /// `None` when the sensor could not attribute this connection to a
    /// process (Global Constraint #5) — the pipeline then emits no
    /// `process` and no `CONNECTED_TO` edge, rather than guessing.
    pub pid: Option<u32>,
    /// Always populated directly from the `/proc/net/tcp` row's `uid`
    /// column, independent of whether pid attribution succeeded.
    pub uid: u32,
    /// Empty when `pid` is `None`, or when `pid` resolved but
    /// `/proc/<pid>/exe`/`/proc/<pid>/comm` could not be read (the process
    /// may have exited between the fd-scan and the read).
    pub exe_path: String,
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the sensor's own clock at the poll
    /// tick this connection's state change was observed (`/proc/net/tcp`
    /// carries no per-connection timestamp of its own).
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}

/// A DNS query+response record (ARCHITECTURE.md §6's DNS STANDARD row:
/// "query+response on watched resolvers"). No live sensor emits this raw
/// shape in this phase (Phase 3 plan Global Constraints #6) — it exists so
/// the full pipeline is real and tested via the Synthetic sensor ahead of a
/// later phase's real backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEventRaw {
    pub query: String,
    /// DNS record type queried, e.g. `"A"`, `"AAAA"`, `"CNAME"`.
    pub qtype: String,
    /// Empty when the query did not resolve (NXDOMAIN, timeout) — still a
    /// valid, storable `DNS_QUERY` event; `dns.response_ips` being empty is
    /// itself sometimes the interesting signal.
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
    /// Same best-effort-attribution shape as `NetworkEventRaw` — a real
    /// pcap/eBPF DNS backend has the same "who asked" attribution problem
    /// a passive capture faces without also correlating process state.
    pub pid: Option<u32>,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}

/// The four session-lifecycle operations this phase emits — ARCHITECTURE.md
/// §9.3's whole `IDENTITY:` taxonomy row. Each maps 1:1 onto one standard
/// auditd record type (Phase 4a plan Global Constraints #3):
/// `Login` <- `type=USER_LOGIN`, `Logout` <- `type=USER_LOGOUT`,
/// `SessionStart` <- `type=USER_START` (PAM session_open),
/// `SessionEnd` <- `type=USER_END` (PAM session_close).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityOperation {
    Login,
    Logout,
    SessionStart,
    SessionEnd,
}

/// The three privilege transitions this phase emits (Phase 4a plan Global
/// Constraints #3). `UidChange` <- `type=SYSCALL syscall=105` (`setuid(2)`
/// on x86_64), `GidChange` <- `type=SYSCALL syscall=106` (`setgid(2)`),
/// `Sudo` <- `type=USER_CMD`. `setresuid`/`setresgid`/`capset` are
/// deliberately not parsed this phase — see the plan's Global Constraint #3
/// for why, and note that adding them is a `match`-arm change here plus one
/// in the sensor's parser, not a redesign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeOperation {
    UidChange,
    GidChange,
    Sudo,
}

/// A session-lifecycle record, parsed from one auditd `USER_*` line.
///
/// Unlike `FileEventRaw`, this is assembled from a *single* record, not a
/// correlated group — but that record has two nested layers: outer
/// `key=value` pairs plus a single-quoted `msg='...'` sub-record. The
/// sensor's parser splits those before tokenizing (Phase 4a plan Global
/// Constraint #9); by the time this struct exists, both layers are merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEventRaw {
    pub operation: IdentityOperation,
    /// The kernel audit session id, from the record's `ses=` field, kept as
    /// a string rather than an integer: it is an opaque correlation handle
    /// (§9.2's `SessionRef.session_id` is a string), auditd prints
    /// `ses=4294967295` for "no session", and a future non-audit backend
    /// (systemd-logind, utmp) may not produce integers at all.
    pub session_id: String,
    /// The pid that performed the login — `sshd`, `login`, `su`, etc. This
    /// is the process the Pipeline's `SessionResolver` roots the session's
    /// pid subtree at (plan Global Constraint #5).
    pub pid: u32,
    /// The record's own `uid=` — the uid of the *authenticating* process
    /// (usually 0 for sshd), not necessarily the user who logged in. The
    /// user who logged in is `auid`/`username`.
    pub uid: u32,
    /// The audit login uid, from `auid=`. `None` when the record omits it
    /// or prints the unset sentinel.
    pub auid: Option<u32>,
    /// From the nested `msg='... acct="alice" ...'`. `None` when absent —
    /// `USER_LOGIN` often carries `id=<uid>` instead of `acct=`.
    pub username: Option<String>,
    /// From the nested `terminal=`. `None` when the record printed `?`.
    pub terminal: Option<String>,
    /// From the nested `addr=`. `None` when the record printed `?` (a local
    /// console login has no remote address) — never the literal `"?"`.
    pub remote_addr: Option<String>,
    /// The authenticating program's file stem, derived from the nested
    /// `exe=` (e.g. `"sshd"`, `"login"`, `"su"`). This is what lands in
    /// §9.2's `SessionRef.auth_method`. `None` when `exe=` is absent.
    pub auth_method: Option<String>,
    /// From the nested `res=`: `res=success` -> true, anything else ->
    /// false. A `USER_LOGIN` failure that still carries a real (non-sentinel)
    /// `ses=` is a real, storable event with `success: false` — but the
    /// common case, a login PAM never opened a session for, prints auditd's
    /// `(unsigned)-1` "no session" sentinel in `ses=` and is dropped
    /// upstream by the session-required gate before `success` is ever read,
    /// same as any other session-less `USER_*` record (Global Constraint
    /// #9's disclosed drop).
    pub success: bool,
    /// From the nested `exe=`, full path. Empty string when absent.
    pub exe_path: String,
    /// The basename of `exe_path` — `USER_*` records carry no `comm=`, so
    /// unlike `SYSCALL` records this is derived, not observed.
    pub comm: String,
    /// Wall-clock nanoseconds, UTC, from the audit event header.
    pub timestamp_ns: u64,
    /// The originating audit event's serial, retained for provenance so an
    /// operator can find the exact record in the source log.
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// A privilege-transition record.
///
/// `UidChange`/`GidChange` come from `type=SYSCALL` records, which carry
/// `gid=`/`euid=`/`egid=` — so those three are `Some` for them. `Sudo`
/// comes from `type=USER_CMD`, which carries only `uid=`/`auid=`/`ses=`, so
/// they are `None` there and the Normalize stage tags the resulting event
/// `USER_REF_PARTIAL` (plan Global Constraint #6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEventRaw {
    pub operation: PrivilegeOperation,
    pub pid: u32,
    /// `0` for `Sudo`: `USER_CMD` records carry no `ppid=`. The Enrich
    /// stage treats ppid 0 as "no parent to inherit a session from", the
    /// same convention `normalize`'s existing `current_ppid` helper already
    /// uses for events whose `event_data` has no `ppid`.
    pub ppid: u32,
    /// The acting (real) uid *before* the transition.
    pub uid: u32,
    pub gid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    pub auid: Option<u32>,
    /// From `ses=`. `None` when the record omits it.
    pub session_id: Option<String>,
    /// The acting user's name when the record reports one. Always `None`
    /// for `SYSCALL`-derived records (audit does not resolve names).
    pub username: Option<String>,
    /// The uid being switched **to**, decoded from the `SYSCALL` record's
    /// `a0=` (setuid's first argument, lowercase hex). `None` for `Sudo`
    /// (plan Global Constraint #9: `USER_CMD` does not reliably report the
    /// target account) and `None` when `a0` decodes to `0xffffffff`, which
    /// is `(uid_t)-1`, i.e. "leave unchanged".
    pub target_uid: Option<u32>,
    /// The gid being switched **to**, decoded from `setgid`'s `a0=`. Same
    /// `-1` handling as `target_uid`. Always `None` for `UidChange`/`Sudo`.
    pub target_gid: Option<u32>,
    /// The command sudo was asked to run, hex-decoded from `USER_CMD`'s
    /// `cmd=` field. `None` for `SYSCALL`-derived records.
    pub command: Option<String>,
    /// `SYSCALL`'s `success=yes` or `USER_CMD`'s nested `res=success`.
    pub success: bool,
    pub exe_path: String,
    /// From `SYSCALL`'s `comm=`; the basename of `exe_path` for `Sudo`.
    pub comm: String,
    pub timestamp_ns: u64,
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// The two systemd unit-lifecycle operations this phase's audit-backed
/// sensor observes (plan Global Constraint #1). Each maps 1:1 onto one
/// standard auditd record type systemd itself emits when audit is enabled:
/// `Start` <- `type=SERVICE_START`, `Stop` <- `type=SERVICE_STOP`. Unlike
/// Identity/Privilege's records, the outer `pid=`/`uid=` are genuinely
/// systemd's own (typically `pid=1 uid=0`), not an attacker-controlled
/// process — there is no process identity to correlate here, only session
/// identity when the record's own `ses=` reports one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemdOperation {
    Start,
    Stop,
}

/// A systemd unit start/stop record, parsed from one auditd `SERVICE_START`/
/// `SERVICE_STOP` line. Same nested `outer key=value` + single-quoted
/// `msg='...'` shape as Identity/Privilege's `USER_*` records (plan Global
/// Constraint #7) — `crate::osiris_fileutil::split_record` (shared, not
/// reimplemented) handles both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdEventRaw {
    pub operation: SystemdOperation,
    /// From the nested `msg='unit=...'`, full unit name including its
    /// `.service`/`.timer` suffix.
    pub unit_name: String,
    /// The outer `pid=` — genuinely systemd's own pid (typically `1`) on a
    /// real host, not an actor's process. Kept rather than discarded: it is
    /// what the record actually reports, and Normalize/Enrich treat it
    /// exactly like any other honestly-reported-but-uninteresting pid
    /// (`PROCESS_KEY_PROVISIONAL` if never independently observed).
    pub pid: u32,
    pub uid: u32,
    /// From the outer `auid=`. `None` when the record omits it or prints
    /// the unset sentinel — systemd does not always have an actor's login
    /// uid to report (e.g. a unit started at boot, with no D-Bus caller).
    pub auid: Option<u32>,
    /// From the outer `ses=`. `None` when absent/unset. When present, this
    /// is the *direct observation* `normalize_systemd_event` uses to
    /// populate `CanonicalEvent.session` (plan Global Constraint #3) —
    /// exactly the same pattern `PrivilegeEventRaw.session_id` already
    /// established in Phase 4a.
    pub session_id: Option<String>,
    /// From the nested `res=`: `res=success` -> true.
    pub success: bool,
    /// From the nested `exe=`, full path (typically
    /// `/usr/lib/systemd/systemd`).
    pub exe_path: String,
    /// From the nested `comm=` (typically `"systemd"`).
    pub comm: String,
    pub timestamp_ns: u64,
    pub audit_serial: Option<u64>,
    pub source: RawEventSource,
}

/// Which of Persistence Monitor's config-declared watch targets a changed
/// path belongs to (plan Global Constraint #4). Explicitly set by the
/// sensor from its own config — never inferred by pattern-matching the path
/// string. `SystemdUnit`/`SystemdTimer` are the one place this phase
/// distinguishes *within* a single watch target, by file extension, since a
/// `systemd_unit_dir` target's directory holds both kinds of file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceCheckpointKind {
    SystemdUnit,
    SystemdTimer,
    Cron,
    ShellProfile,
    LdPreload,
    Sudoers,
}

/// The three lifecycle transitions Persistence Monitor's periodic scan-and-
/// diff observes for one watched path (plan Global Constraint #8: the very
/// first scan after Agent start seeds a baseline silently and emits none of
/// these for whatever it finds already present).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceOperation {
    Created,
    Modified,
    Removed,
}

/// A persistence-checkpoint-path lifecycle record, from Persistence
/// Monitor's periodic scan (never from Linux Audit — plan Global Constraint
/// #1). No process/session identity is ever attached: the scanner is not
/// triggered by a process event, so any pid it reported would be
/// fabricated. `content_hash`/`size` are always `None` for `Removed` (there
/// is nothing left to hash — plan-mandated, not an oversight).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEventRaw {
    pub operation: PersistenceOperation,
    pub checkpoint_kind: PersistenceCheckpointKind,
    pub path: String,
    /// SHA-256 hex digest of the file's current content. `None` for
    /// `Removed`.
    pub content_hash: Option<String>,
    /// `None` for `Removed`.
    pub size: Option<u64>,
    pub timestamp_ns: u64,
    /// Always `RawEventSource::Procfs` in practice (plan Global Constraint
    /// #1 — no audit-log equivalent exists for a generic file-content
    /// scan); kept as the full enum rather than hardcoded so a future
    /// fanotify-backed variant is a value change here, not a type change.
    pub source: RawEventSource,
}

/// The four container lifecycle transitions this phase's fallback sensor
/// observes (Phase 5 plan Global Constraint #7). A cgroup directory
/// appearing is reported as `Create` immediately followed by `Start` (a
/// one-shot poll cannot distinguish "just created" from "just started");
/// a cgroup directory disappearing is `Stop` immediately followed by
/// `Destroy` — both pairings disclosed via `event_data.observed_transition`
/// at normalize time, never silently merged into one guessed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerOperation {
    Create,
    Start,
    Stop,
    Destroy,
}

/// A container lifecycle record. Phase 5 plan Global Constraint #6: the
/// cgroup-only fallback backend that emits this in practice never has
/// `image`/`pod_ref` metadata — `image`/`runtime` are honest empty/`"cgroup"`
/// values in that case, not fabricated. `pid` is the container's resolved
/// init process, when the poller could derive one from the cgroup's
/// `cgroup.procs` file; `None` when it couldn't (plan Global Constraint #1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEventRaw {
    pub operation: ContainerOperation,
    pub container_id: String,
    /// `""` when the backend has no image metadata (cgroup-only
    /// correlation, plan Global Constraint #6).
    pub image: String,
    /// `"cgroup"` for the fallback backend (plan Global Constraint #6);
    /// `"docker"`/`"containerd"`/`"cri-o"` reserved for the deferred
    /// runtime-API primary backend (plan Global Constraint #1).
    pub runtime: String,
    pub cgroup_path: String,
    pub pid: Option<u32>,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub timestamp_ns: u64,
    pub source: RawEventSource,
}

/// The Agent's periodic aggregated health report (Phase 9d-1). Built by
/// the Agent's own supervisor loop, not sensed from any raw source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthRaw {
    pub agent_version: String,
    pub health: osiris_health::AgentHealth,
    pub timestamp_ns: u64,
}

/// The shape sensors emit onto their output channel (ARCHITECTURE.md §7.1
/// step 1, "Collect"). Phase 1 scoped this to Process/Exec; Phase 2 added
/// File; Phase 3 added Network and Dns; Phase 4a adds Identity and
/// Privilege; Phase 4b added Systemd and Persistence; Phase 5 adds
/// Container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessExec(ProcessExecRaw),
    File(FileEventRaw),
    Network(NetworkEventRaw),
    Dns(DnsEventRaw),
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
    Systemd(SystemdEventRaw),
    Persistence(PersistenceEventRaw),
    Container(ContainerEventRaw),
    AgentHealth(AgentHealthRaw),
}

impl RawEvent {
    /// The originating backend's wall-clock timestamp, regardless of
    /// variant — used by sensors for their `last_event_at` health field
    /// without matching on the variant at every call site.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RawEvent::ProcessExec(p) => p.timestamp_ns,
            RawEvent::File(f) => f.timestamp_ns,
            RawEvent::Network(n) => n.timestamp_ns,
            RawEvent::Dns(d) => d.timestamp_ns,
            RawEvent::Identity(i) => i.timestamp_ns,
            RawEvent::Privilege(p) => p.timestamp_ns,
            RawEvent::Systemd(s) => s.timestamp_ns,
            RawEvent::Persistence(p) => p.timestamp_ns,
            RawEvent::Container(c) => c.timestamp_ns,
            RawEvent::AgentHealth(a) => a.timestamp_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_raw() -> FileEventRaw {
        FileEventRaw {
            operation: FileOperation::Create,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some((8u64 << 32) | 1),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn file_raw_round_trips_through_json() {
        let raw = RawEvent::File(file_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::File(f) => {
                assert_eq!(f.path, "/var/www/html/shell.php");
                assert_eq!(f.operation, FileOperation::Create);
                assert_eq!(f.inode, Some(131075));
            }
            other => panic!("expected RawEvent::File, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_both_variants() {
        assert_eq!(
            RawEvent::File(file_raw()).timestamp_ns(),
            1_690_000_000_123_000_000
        );
        let exec = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe_path: "/bin/init".to_string(),
            comm: "init".to_string(),
            timestamp_ns: 42,
            start_time_mono: 42,
            source: RawEventSource::Synthetic,
        });
        assert_eq!(exec.timestamp_ns(), 42);
    }

    fn network_raw() -> NetworkEventRaw {
        NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: "203.0.113.50".to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    fn dns_raw() -> DnsEventRaw {
        DnsEventRaw {
            query: "cdn-assets.xyz".to_string(),
            qtype: "A".to_string(),
            response_ips: vec!["203.0.113.50".to_string()],
            ttl: Some(300),
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_690_000_004_000_000_000,
            source: RawEventSource::Synthetic,
        }
    }

    #[test]
    fn network_raw_round_trips_through_json() {
        let raw = RawEvent::Network(network_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => {
                assert_eq!(n.remote_addr, "203.0.113.50");
                assert_eq!(n.operation, NetworkOperation::Connect);
                assert_eq!(n.pid, Some(300));
            }
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }

    #[test]
    fn dns_raw_round_trips_through_json() {
        let raw = RawEvent::Dns(dns_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Dns(d) => {
                assert_eq!(d.query, "cdn-assets.xyz");
                assert_eq!(d.response_ips, vec!["203.0.113.50".to_string()]);
            }
            other => panic!("expected RawEvent::Dns, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_network_and_dns_variants() {
        assert_eq!(
            RawEvent::Network(network_raw()).timestamp_ns(),
            1_690_000_005_000_000_000
        );
        assert_eq!(
            RawEvent::Dns(dns_raw()).timestamp_ns(),
            1_690_000_004_000_000_000
        );
    }

    /// A connection the sensor could not attribute to a pid (Global
    /// Constraint #5) still round-trips — `pid: None` must not break
    /// (de)serialization.
    #[test]
    fn network_raw_with_no_pid_attribution_round_trips() {
        let mut raw = network_raw();
        raw.pid = None;
        raw.exe_path = String::new();
        raw.comm = String::new();
        let json = serde_json::to_string(&RawEvent::Network(raw)).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Network(n) => assert_eq!(n.pid, None),
            other => panic!("expected RawEvent::Network, got {other:?}"),
        }
    }

    fn identity_raw() -> IdentityEventRaw {
        IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: "3".to_string(),
            pid: 1200,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Audit,
        }
    }

    fn privilege_raw() -> PrivilegeEventRaw {
        PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 1400,
            ppid: 1300,
            uid: 1000,
            gid: Some(1000),
            euid: Some(1000),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 1_690_000_005_000_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn identity_raw_round_trips_through_json() {
        let raw = RawEvent::Identity(identity_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert_eq!(i.session_id, "3");
                assert_eq!(i.remote_addr.as_deref(), Some("198.51.100.10"));
                assert_eq!(i.auid, Some(1000));
            }
            other => panic!("expected RawEvent::Identity, got {other:?}"),
        }
    }

    #[test]
    fn privilege_raw_round_trips_through_json() {
        let raw = RawEvent::Privilege(privilege_raw());
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::UidChange);
                assert_eq!(p.target_uid, Some(0));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.euid, Some(1000));
            }
            other => panic!("expected RawEvent::Privilege, got {other:?}"),
        }
    }

    /// A local console login has no remote address and a sudo record often
    /// reports no target account (Global Constraint #9) — both must
    /// round-trip as `None`, never as a placeholder string.
    #[test]
    fn absent_optional_fields_round_trip_as_none() {
        let mut identity = identity_raw();
        identity.remote_addr = None;
        identity.username = None;
        let json = serde_json::to_string(&RawEvent::Identity(identity)).unwrap();
        match serde_json::from_str::<RawEvent>(&json).unwrap() {
            RawEvent::Identity(i) => {
                assert_eq!(i.remote_addr, None);
                assert_eq!(i.username, None);
            }
            other => panic!("expected RawEvent::Identity, got {other:?}"),
        }

        let mut privilege = privilege_raw();
        privilege.operation = PrivilegeOperation::Sudo;
        privilege.target_uid = None;
        privilege.command = Some("/usr/bin/whoami".to_string());
        let json = serde_json::to_string(&RawEvent::Privilege(privilege)).unwrap();
        match serde_json::from_str::<RawEvent>(&json).unwrap() {
            RawEvent::Privilege(p) => {
                assert_eq!(p.target_uid, None);
                assert_eq!(p.command.as_deref(), Some("/usr/bin/whoami"));
            }
            other => panic!("expected RawEvent::Privilege, got {other:?}"),
        }
    }

    #[test]
    fn timestamp_accessor_works_for_identity_and_privilege_variants() {
        assert_eq!(
            RawEvent::Identity(identity_raw()).timestamp_ns(),
            1_690_000_000_123_000_000
        );
        assert_eq!(
            RawEvent::Privilege(privilege_raw()).timestamp_ns(),
            1_690_000_005_000_000_000
        );
    }

    fn systemd_raw() -> SystemdEventRaw {
        SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: "sshd.service".to_string(),
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: 1_690_000_000_123_000_000,
            audit_serial: Some(501),
            source: RawEventSource::Audit,
        }
    }

    #[test]
    fn systemd_raw_event_round_trips_through_raw_event() {
        let raw = RawEvent::Systemd(systemd_raw());
        assert_eq!(raw.timestamp_ns(), 1_690_000_000_123_000_000);
        match raw {
            RawEvent::Systemd(s) => {
                assert_eq!(s.operation, SystemdOperation::Start);
                assert_eq!(s.unit_name, "sshd.service");
                assert_eq!(s.session_id.as_deref(), Some("3"));
            }
            other => panic!("expected RawEvent::Systemd, got {other:?}"),
        }
    }

    fn persistence_raw() -> PersistenceEventRaw {
        PersistenceEventRaw {
            operation: PersistenceOperation::Created,
            checkpoint_kind: PersistenceCheckpointKind::SystemdUnit,
            path: "/etc/systemd/system/backdoor.service".to_string(),
            content_hash: Some("a".repeat(64)),
            size: Some(128),
            timestamp_ns: 1_690_000_010_000_000_000,
            source: RawEventSource::Procfs,
        }
    }

    #[test]
    fn persistence_raw_event_round_trips_through_raw_event() {
        let raw = RawEvent::Persistence(persistence_raw());
        assert_eq!(raw.timestamp_ns(), 1_690_000_010_000_000_000);
        match raw {
            RawEvent::Persistence(p) => {
                assert_eq!(p.operation, PersistenceOperation::Created);
                assert_eq!(p.checkpoint_kind, PersistenceCheckpointKind::SystemdUnit);
                assert_eq!(p.path, "/etc/systemd/system/backdoor.service");
                assert_eq!(p.content_hash.as_deref(), Some("a".repeat(64).as_str()));
            }
            other => panic!("expected RawEvent::Persistence, got {other:?}"),
        }
    }

    /// A removed artifact carries no content hash — there is nothing left
    /// to hash, and inventing one (e.g. reusing the last-known hash) would
    /// misrepresent a deletion as a content fact.
    fn container_raw() -> ContainerEventRaw {
        ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: "a".repeat(64),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: "/system.slice/docker-".to_string() + &"a".repeat(64) + ".scope",
            pid: Some(4242),
            pod_name: None,
            pod_namespace: None,
            timestamp_ns: 1_690_000_020_000_000_000,
            source: RawEventSource::Procfs,
        }
    }

    #[test]
    fn container_raw_event_round_trips_through_raw_event() {
        let raw = RawEvent::Container(container_raw());
        assert_eq!(raw.timestamp_ns(), 1_690_000_020_000_000_000);
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEvent = serde_json::from_str(&json).unwrap();
        match back {
            RawEvent::Container(c) => {
                assert_eq!(c.operation, ContainerOperation::Start);
                assert_eq!(c.container_id, "a".repeat(64));
                assert_eq!(c.pid, Some(4242));
                assert_eq!(c.runtime, "cgroup");
            }
            other => panic!("expected RawEvent::Container, got {other:?}"),
        }
    }

    /// A `Destroy` event's process may already be reaped — `pid: None`
    /// must round-trip, never be coerced into a fabricated value.
    #[test]
    fn a_destroyed_container_event_may_carry_no_pid() {
        let mut raw = container_raw();
        raw.operation = ContainerOperation::Destroy;
        raw.pid = None;
        let json = serde_json::to_string(&RawEvent::Container(raw)).unwrap();
        match serde_json::from_str::<RawEvent>(&json).unwrap() {
            RawEvent::Container(c) => {
                assert_eq!(c.operation, ContainerOperation::Destroy);
                assert_eq!(c.pid, None);
            }
            other => panic!("expected RawEvent::Container, got {other:?}"),
        }
    }

    #[test]
    fn a_removed_persistence_event_carries_no_content_hash() {
        let mut raw = persistence_raw();
        raw.operation = PersistenceOperation::Removed;
        raw.content_hash = None;
        raw.size = None;
        let event = RawEvent::Persistence(raw);
        match event {
            RawEvent::Persistence(p) => {
                assert!(p.content_hash.is_none());
                assert!(p.size.is_none());
            }
            other => panic!("expected RawEvent::Persistence, got {other:?}"),
        }
    }
}
