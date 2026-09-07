use std::collections::HashMap;

use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
use osiris_sensor_api::{
    IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation, RawEventSource,
};

/// auditd's `(unsigned)-1` sentinel, printed for an unset `auid=`/`ses=`
/// and for a `setuid`/`setgid` argument meaning "leave this id unchanged".
const UNSET_ID: &str = "4294967295";

/// One auditd record, split into the three layers a `USER_*` line actually
/// has: the `type=… msg=audit(<secs>.<millis>:<serial>):` header, the outer
/// `key=value` body, and the single-quoted `msg='…'` sub-record.
///
/// This split is mandatory, not a convenience (Phase 4a plan Global
/// Constraint #9): `osiris_fileutil::tokenize` returns a `HashMap`, so
/// tokenizing a whole `USER_*` line lets the nested `msg='…'` overwrite the
/// header's `msg=audit(…)` value and destroys the timestamp and serial.
/// Nothing in this crate ever calls `tokenize` on a whole `USER_*` line.
#[derive(Debug, Clone)]
pub struct RecordParts {
    pub id: AuditMsgId,
    pub record_type: String,
    pub outer: HashMap<String, String>,
    pub inner: HashMap<String, String>,
}

impl RecordParts {
    /// Reads a field from either layer, outer first. The two layers never
    /// carry the same key in the record types this sensor parses, so the
    /// precedence is a tiebreak that is not exercised in practice — but it
    /// is defined here rather than left to iteration order.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.outer
            .get(key)
            .or_else(|| self.inner.get(key))
            .map(String::as_str)
    }
}

/// Splits one auditd line into header / outer body / inner `msg='…'`.
/// Returns `None` for any line with no parseable `msg=audit(…):` header —
/// never panics, never half-parses.
pub fn split_record(line: &str) -> Option<RecordParts> {
    // The header always ends `…:<serial>): `. Splitting there is exact: the
    // sequence `"): "` cannot occur earlier, because everything before it
    // is `type=<T> msg=audit(<digits>.<digits>:<digits>)`.
    let end = line.find("): ")?;
    // `..end + 2` keeps the trailing `:`, which `parse_audit_msg_id`
    // explicitly accepts (see its doc comment in osiris-fileutil).
    let header = &line[..end + 2];
    let body = &line[end + 3..];

    let header_fields = tokenize(header);
    let id = parse_audit_msg_id(header_fields.get("msg")?)?;
    let record_type = header_fields.get("type")?.clone();

    // Carve the nested sub-record out of the body before tokenizing what
    // remains, so neither layer's fields can shadow the other's.
    let (outer_text, inner_text) = match body.find("msg='") {
        Some(start) => {
            let after = &body[start + 5..];
            match after.find('\'') {
                Some(close) => {
                    let mut outer = String::with_capacity(body.len());
                    outer.push_str(&body[..start]);
                    outer.push_str(&after[close + 1..]);
                    (outer, after[..close].to_string())
                }
                // An unterminated quote: treat the remainder as the inner
                // sub-record rather than dropping the record outright. The
                // caller's required-field lookups then decide whether
                // enough survived to build an event.
                None => (body[..start].to_string(), after.to_string()),
            }
        }
        None => (body.to_string(), String::new()),
    };

    Some(RecordParts {
        id,
        record_type,
        outer: tokenize(&outer_text),
        inner: tokenize(&inner_text),
    })
}

/// The two disjoint record families this sensor emits (Phase 4a plan Global
/// Constraint #4). One `LineTailer` over one audit log produces both; there
/// is no separate privilege sensor in ARCHITECTURE.md §4.3's catalog to
/// produce the second.
#[derive(Debug, Clone)]
pub enum IdentityRecord {
    Identity(IdentityEventRaw),
    Privilege(PrivilegeEventRaw),
}

/// Parses one auditd line into whichever raw event it represents, or `None`
/// when the line is not one of this phase's seven record shapes.
///
/// Deliberate drops (all disclosed in the plan's Global Constraints #3/#9,
/// none of them silent guesses):
/// * every record type other than `USER_LOGIN`/`USER_LOGOUT`/`USER_START`/
///   `USER_END`/`USER_CMD`/`SYSCALL`;
/// * a `SYSCALL` record whose `syscall=` is not 105 (`setuid`) or 106
///   (`setgid`) — `setresuid`/`setresgid`/`capset` are out of scope;
/// * a `USER_*` session-lifecycle record with no usable `ses=` (absent, or
///   the `4294967295` unset sentinel). Such a record names no session, so
///   nothing could ever correlate to it and Task 2's `validate` would tag
///   the resulting event INVALID. A `USER_CMD` is *not* dropped for the
///   same reason: it names a command, and its session is `Option`al.
pub fn parse_record(line: &str) -> Option<IdentityRecord> {
    let parts = split_record(line)?;
    match parts.record_type.as_str() {
        "USER_LOGIN" => identity(&parts, IdentityOperation::Login),
        "USER_LOGOUT" => identity(&parts, IdentityOperation::Logout),
        "USER_START" => identity(&parts, IdentityOperation::SessionStart),
        "USER_END" => identity(&parts, IdentityOperation::SessionEnd),
        "USER_CMD" => sudo(&parts, line),
        "SYSCALL" => match parts.get("syscall")?.parse::<u32>().ok()? {
            105 => syscall_privilege(&parts, PrivilegeOperation::UidChange),
            106 => syscall_privilege(&parts, PrivilegeOperation::GidChange),
            _ => None,
        },
        _ => None,
    }
}

fn identity(parts: &RecordParts, operation: IdentityOperation) -> Option<IdentityRecord> {
    let session_id = usable_session(parts.get("ses"))?;
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(IdentityRecord::Identity(IdentityEventRaw {
        operation,
        session_id,
        pid: parts.get("pid")?.parse().ok()?,
        uid: parts.get("uid")?.parse().ok()?,
        auid: parse_id(parts.get("auid")),
        // `acct="name"` when the record carries a name; `USER_LOGIN` usually
        // reports `id=<uid>` instead, and a uid is not a name — so this
        // stays None rather than being back-derived (§9's confidence
        // boundary: unknown is None, never invented).
        username: unknown_to_none(parts.get("acct")).map(str::to_string),
        terminal: unknown_to_none(parts.get("terminal")).map(str::to_string),
        remote_addr: unknown_to_none(parts.get("addr")).map(str::to_string),
        auth_method: basename(&exe_path),
        success: parts.get("res") == Some("success"),
        comm: basename(&exe_path).unwrap_or_default(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

fn syscall_privilege(
    parts: &RecordParts,
    operation: PrivilegeOperation,
) -> Option<IdentityRecord> {
    // setuid/setgid's single argument, lowercase hex with no `0x` prefix.
    // `ffffffff` is `(uid_t)-1` — "leave unchanged", not a transition to
    // 4,294,967,295.
    let target = parts
        .get("a0")
        .and_then(|a0| u32::from_str_radix(a0, 16).ok())
        .filter(|v| *v != u32::MAX);
    let (target_uid, target_gid) = match operation {
        PrivilegeOperation::UidChange => (target, None),
        PrivilegeOperation::GidChange => (None, target),
        // Unreachable: only the two SYSCALL arms call this.
        PrivilegeOperation::Sudo => (None, None),
    };
    Some(IdentityRecord::Privilege(PrivilegeEventRaw {
        operation,
        pid: parts.get("pid")?.parse().ok()?,
        ppid: parts.get("ppid").and_then(|v| v.parse().ok()).unwrap_or(0),
        uid: parts.get("uid")?.parse().ok()?,
        gid: parts.get("gid").and_then(|v| v.parse().ok()),
        euid: parts.get("euid").and_then(|v| v.parse().ok()),
        egid: parts.get("egid").and_then(|v| v.parse().ok()),
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        // audit does not resolve uids to names on SYSCALL records.
        username: None,
        target_uid,
        target_gid,
        command: None,
        success: parts.get("success") == Some("yes"),
        exe_path: parts.get("exe").unwrap_or_default().to_string(),
        comm: parts.get("comm").unwrap_or_default().to_string(),
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

fn sudo(parts: &RecordParts, line: &str) -> Option<IdentityRecord> {
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(IdentityRecord::Privilege(PrivilegeEventRaw {
        operation: PrivilegeOperation::Sudo,
        pid: parts.get("pid")?.parse().ok()?,
        // USER_CMD carries no `ppid=`. 0 is the codebase's "no parent
        // reported" convention (see `PrivilegeEventRaw.ppid`'s doc comment
        // and `enrich::current_ppid`), and `SessionResolver::attach` treats
        // it as "nothing to inherit from" — never as pid 0.
        ppid: 0,
        uid: parts.get("uid")?.parse().ok()?,
        // USER_CMD reports none of these; Task 2 tags the resulting event
        // USER_REF_PARTIAL rather than mirroring them silently.
        gid: None,
        euid: None,
        egid: None,
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        username: unknown_to_none(parts.get("acct")).map(str::to_string),
        // Global Constraint #9: `USER_CMD` does not reliably report the
        // target account across distributions, so no target is claimed and
        // Task 2 therefore mints no EXECUTED_AS edge for a sudo event.
        target_uid: None,
        target_gid: None,
        command: parts
            .get("cmd")
            .map(|cmd| decode_untrusted_string(line, "cmd", cmd)),
        success: parts.get("res") == Some("success"),
        comm: basename(&exe_path).unwrap_or_default(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    }))
}

/// auditd prints a literal `?` for an unknown `addr=`/`hostname=`/
/// `terminal=` — a local console login has no remote address. That is
/// "unknown", so it becomes `None`; `Some("?")` must never reach a
/// `SessionRef` (Phase 4a plan Global Constraint #9).
fn unknown_to_none(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "?" && *v != "(none)")
}

/// Parses a uid-like field, mapping auditd's unset sentinel to `None`
/// rather than to 4,294,967,295.
fn parse_id(value: Option<&str>) -> Option<u32> {
    value.filter(|v| *v != UNSET_ID)?.parse().ok()
}

/// A session id that can actually be correlated: present, non-empty, and
/// not the unset sentinel.
fn usable_session(value: Option<&str>) -> Option<String> {
    value
        .filter(|v| !v.is_empty() && *v != UNSET_ID && *v != "?")
        .map(str::to_string)
}

/// The file stem of an executable path — `"/usr/sbin/sshd"` -> `"sshd"`.
/// This is what lands in `SessionRef.auth_method` (§9.2) and, for records
/// carrying no `comm=`, in `comm`. Returns `None` for an empty path rather
/// than an empty string, so "no exe reported" stays distinguishable.
fn basename(exe_path: &str) -> Option<String> {
    let stem = exe_path.rsplit('/').next().unwrap_or_default();
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

/// The kernel logs a string via `audit_log_untrustedstring`: a value
/// containing any byte outside printable-ASCII-minus-quote (a space, most
/// obviously, which every real sudo command line has) is logged
/// **unquoted, as uppercase hex** instead of `key="value"`. `cmd=` is the
/// one field this sensor reads that carries such a value, so it is decoded
/// here — exactly as `osiris_sensors_fs::audit_record` decodes `name=` and
/// `cwd=`. That crate is a sibling sensor, so the helper is duplicated
/// rather than imported: one sensor never depends on another (§4.2).
///
/// `tokenize` already strips quotes, so the quoted/unquoted distinction
/// cannot be read back off its output — a legitimately quoted, all-hex
/// command (`cmd="deadbeef"`) must not be mistaken for an encoded one.
/// This checks the raw line for the literal `cmd="` marker instead.
fn decode_untrusted_string(line: &str, key: &str, raw_value: &str) -> String {
    if line.contains(&format!("{key}=\"")) {
        return raw_value.to_string();
    }
    decode_hex(raw_value).unwrap_or_else(|| raw_value.to_string())
}

fn decode_hex(raw: &str) -> Option<String> {
    if raw.len() < 2 || raw.len() % 2 != 0 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let hex_pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(hex_pair, 16).ok()?);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{IdentityOperation, PrivilegeOperation, RawEventSource};

    // --- The seven record shapes this phase emits, in real auditd text ---

    /// `USER_LOGIN` reports the logging-in account as `id=<uid>` rather
    /// than `acct="name"` on most builds — hence `username: None` for this
    /// line, with `acct=` exercised on USER_START below.
    const USER_LOGIN: &str = r#"type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_START: &str = r#"type=USER_START msg=audit(1690000000.130:457): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_END: &str = r#"type=USER_END msg=audit(1690000090.000:512): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_LOGOUT: &str = r#"type=USER_LOGOUT msg=audit(1690000090.010:513): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    /// `cmd=` is hex-encoded whenever the command contains a byte outside
    /// printable-ASCII-minus-quote — which any command line with a space
    /// always does. `2F7573722F62696E2F77686F616D69` is `/usr/bin/whoami`.
    const USER_CMD: &str = r#"type=USER_CMD msg=audit(1690000005.000:469): pid=1400 uid=1000 auid=1000 ses=3 msg='cwd="/home/alice" cmd=2F7573722F62696E2F77686F616D69 exe="/usr/bin/sudo" terminal=pts/0 res=success'"#;
    /// x86_64 syscall 105 is `setuid(2)`; `a0` is its single argument, in
    /// lowercase hex with no `0x` prefix — `a0=0` means "become uid 0".
    const SYSCALL_SETUID: &str = r#"type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;
    /// x86_64 syscall 106 is `setgid(2)`.
    const SYSCALL_SETGID: &str = r#"type=SYSCALL msg=audit(1690000005.020:471): arch=c000003e syscall=106 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;

    // --- The splitter: header / outer body / inner msg ---

    /// Global Constraint #9's load-bearing consequence, stated as a test: a
    /// `USER_*` line has TWO `msg=` fields, and `tokenize`'s `HashMap` keeps
    /// only the last one, so feeding such a line to `tokenize` whole
    /// destroys the audit header. `split_record` must not.
    #[test]
    fn a_whole_user_line_fed_to_tokenize_loses_the_header_but_split_record_does_not() {
        // Proof of the hazard, so this fails loudly if `tokenize`'s
        // contract ever changes underneath us.
        let naive = osiris_fileutil::tokenize(USER_LOGIN);
        assert!(
            osiris_fileutil::parse_audit_msg_id(naive.get("msg").unwrap()).is_none(),
            "the nested msg='...' must be what a naive tokenize sees — if this ever \
             passes, re-read Global Constraint #9 before simplifying the splitter"
        );

        let parts = split_record(USER_LOGIN).expect("must split");
        assert_eq!(parts.id.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(parts.id.serial, 456);
        assert_eq!(parts.record_type, "USER_LOGIN");
    }

    #[test]
    fn split_record_separates_outer_fields_from_the_nested_msg_fields() {
        let parts = split_record(USER_START).expect("must split");
        // Outer body.
        assert_eq!(parts.outer.get("pid").map(String::as_str), Some("1200"));
        assert_eq!(parts.outer.get("uid").map(String::as_str), Some("0"));
        assert_eq!(parts.outer.get("auid").map(String::as_str), Some("1000"));
        assert_eq!(parts.outer.get("ses").map(String::as_str), Some("3"));
        // Inner sub-record.
        assert_eq!(parts.inner.get("acct").map(String::as_str), Some("alice"));
        assert_eq!(
            parts.inner.get("exe").map(String::as_str),
            Some("/usr/sbin/sshd")
        );
        assert_eq!(parts.inner.get("res").map(String::as_str), Some("success"));
        assert_eq!(
            parts.inner.get("addr").map(String::as_str),
            Some("198.51.100.10")
        );
        // `get` reads either layer, outer first.
        assert_eq!(parts.get("ses"), Some("3"));
        assert_eq!(parts.get("acct"), Some("alice"));
        assert_eq!(parts.get("nope"), None);
    }

    /// A `SYSCALL` record has no nested `msg='...'` at all — the splitter
    /// must treat that as the ordinary case, with an empty inner map,
    /// rather than rejecting the line.
    #[test]
    fn split_record_handles_a_record_with_no_nested_msg() {
        let parts = split_record(SYSCALL_SETUID).expect("must split");
        assert_eq!(parts.record_type, "SYSCALL");
        assert!(parts.inner.is_empty());
        assert_eq!(parts.outer.get("syscall").map(String::as_str), Some("105"));
        assert_eq!(parts.outer.get("a0").map(String::as_str), Some("0"));
        assert_eq!(parts.id.serial, 470);
    }

    #[test]
    fn split_record_rejects_a_line_with_no_audit_header() {
        assert!(split_record("this is not an audit record").is_none());
        assert!(split_record("type=USER_LOGIN pid=1200").is_none());
    }

    // --- Identity records ---

    #[test]
    fn parses_a_user_login_into_an_identity_login_event() {
        match parse_record(USER_LOGIN).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert_eq!(i.session_id, "3");
                assert_eq!(i.pid, 1200);
                assert_eq!(i.uid, 0);
                assert_eq!(i.auid, Some(1000));
                // This record reported `id=1000`, not `acct=` — the name is
                // genuinely unknown, so it stays None rather than being
                // back-derived from the uid (Global Constraint #9).
                assert_eq!(i.username, None);
                assert_eq!(i.terminal.as_deref(), Some("/dev/pts/0"));
                assert_eq!(i.remote_addr.as_deref(), Some("198.51.100.10"));
                assert_eq!(i.auth_method.as_deref(), Some("sshd"));
                assert!(i.success);
                assert_eq!(i.exe_path, "/usr/sbin/sshd");
                assert_eq!(i.comm, "sshd");
                assert_eq!(i.timestamp_ns, 1_690_000_000_123_000_000);
                assert_eq!(i.audit_serial, Some(456));
                assert_eq!(i.source, RawEventSource::Audit);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    #[test]
    fn parses_the_other_three_user_record_types_onto_their_operations() {
        for (line, expected) in [
            (USER_START, IdentityOperation::SessionStart),
            (USER_END, IdentityOperation::SessionEnd),
            (USER_LOGOUT, IdentityOperation::Logout),
        ] {
            match parse_record(line).expect("must parse") {
                IdentityRecord::Identity(i) => assert_eq!(i.operation, expected),
                other => panic!("expected an Identity record, got {other:?}"),
            }
        }
    }

    /// `acct="alice"` is the field that does carry a name, and it lives in
    /// the *nested* sub-record, not the outer body.
    #[test]
    fn reads_the_account_name_from_the_nested_sub_record() {
        match parse_record(USER_START).expect("must parse") {
            IdentityRecord::Identity(i) => assert_eq!(i.username.as_deref(), Some("alice")),
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    /// Global Constraint #9's disclosed `?` handling: a local console login
    /// has no remote address, and auditd prints a literal `?`. That must
    /// become `None`, never `Some("?")`.
    #[test]
    fn an_unknown_address_or_terminal_becomes_none_not_a_question_mark() {
        let local = USER_LOGIN
            .replace("hostname=198.51.100.10", "hostname=?")
            .replace("addr=198.51.100.10", "addr=?")
            .replace("terminal=/dev/pts/0", "terminal=?");
        match parse_record(&local).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.remote_addr, None);
                assert_eq!(i.terminal, None);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_login_is_still_emitted_with_success_false() {
        let failed = USER_LOGIN.replace("res=success", "res=failed");
        match parse_record(&failed).expect("must parse") {
            IdentityRecord::Identity(i) => {
                assert_eq!(i.operation, IdentityOperation::Login);
                assert!(!i.success);
            }
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    /// `ses=4294967295` is auditd's `(unsigned)-1` sentinel for "no audit
    /// session" (a daemon-initiated PAM open, say). A session-lifecycle
    /// record naming no session cannot be correlated to anything, and Task
    /// 2's `validate` would tag it INVALID; it is dropped here instead, and
    /// that drop is documented at `parse_record`.
    #[test]
    fn a_user_record_with_the_unset_session_sentinel_is_dropped() {
        assert!(parse_record(&USER_LOGIN.replace("ses=3", "ses=4294967295")).is_none());
        assert!(parse_record(&USER_LOGIN.replace(" ses=3", "")).is_none());
    }

    #[test]
    fn an_unset_auid_sentinel_becomes_none_rather_than_four_billion() {
        let line = USER_LOGIN.replace("auid=1000", "auid=4294967295");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Identity(i) => assert_eq!(i.auid, None),
            other => panic!("expected an Identity record, got {other:?}"),
        }
    }

    // --- Privilege records ---

    #[test]
    fn parses_a_setuid_syscall_into_a_uid_change_with_its_target() {
        match parse_record(SYSCALL_SETUID).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::UidChange);
                assert_eq!(p.pid, 300);
                assert_eq!(p.ppid, 200);
                assert_eq!(p.uid, 1000);
                // A SYSCALL record reports these for real, so they are Some
                // and Task 2 will NOT tag the event USER_REF_PARTIAL.
                assert_eq!(p.gid, Some(1000));
                assert_eq!(p.euid, Some(0));
                assert_eq!(p.egid, Some(1000));
                assert_eq!(p.auid, Some(1000));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.username, None);
                assert_eq!(p.target_uid, Some(0));
                assert_eq!(p.target_gid, None);
                assert_eq!(p.command, None);
                assert!(p.success);
                assert_eq!(p.exe_path, "/usr/bin/sudo");
                assert_eq!(p.comm, "sudo");
                assert_eq!(p.timestamp_ns, 1_690_000_005_010_000_000);
                assert_eq!(p.audit_serial, Some(470));
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_setgid_syscall_into_a_gid_change_with_target_gid_not_target_uid() {
        match parse_record(SYSCALL_SETGID).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::GidChange);
                assert_eq!(p.target_gid, Some(0));
                assert_eq!(
                    p.target_uid, None,
                    "a setgid record must never populate target_uid — Task 2's \
                     EXECUTED_AS edge is keyed on it and EntityRef::User has no gid"
                );
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// `a0=ffffffff` is `(uid_t)-1`: "leave this id unchanged". It is not a
    /// transition to uid 4,294,967,295 and must not be reported as one.
    #[test]
    fn a_minus_one_argument_becomes_none_rather_than_a_four_billion_target() {
        let line = SYSCALL_SETUID.replace("a0=0 ", "a0=ffffffff ");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.target_uid, None),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_setuid_is_still_emitted_with_success_false() {
        let line = SYSCALL_SETUID.replace("success=yes", "success=no");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert!(!p.success),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// Only 105 and 106 are privilege transitions this phase parses. 59
    /// (execve) belongs to the Process/Exec sensor, and 113/114
    /// (setresuid/setresgid) are deliberately out of scope (Global
    /// Constraint #3) — all must be ignored, never guessed at.
    #[test]
    fn other_syscall_numbers_are_ignored_including_the_deliberately_deferred_ones() {
        for nr in ["59", "113", "114", "257", "90"] {
            let line = SYSCALL_SETUID.replace("syscall=105", &format!("syscall={nr}"));
            assert!(
                parse_record(&line).is_none(),
                "syscall={nr} must not produce a privilege event this phase"
            );
        }
    }

    #[test]
    fn parses_a_user_cmd_into_a_sudo_event_with_a_hex_decoded_command() {
        match parse_record(USER_CMD).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.operation, PrivilegeOperation::Sudo);
                assert_eq!(p.pid, 1400);
                // USER_CMD carries no ppid= — 0 is the "no parent reported"
                // convention Task 1 documented, not an invented pid.
                assert_eq!(p.ppid, 0);
                assert_eq!(p.uid, 1000);
                // ...and no gid/euid/egid, so Task 2 tags the resulting
                // event USER_REF_PARTIAL (Global Constraint #6).
                assert_eq!((p.gid, p.euid, p.egid), (None, None, None));
                assert_eq!(p.session_id.as_deref(), Some("3"));
                assert_eq!(p.command.as_deref(), Some("/usr/bin/whoami"));
                // Global Constraint #9: the target account is NOT reliably
                // reported on USER_CMD, so none is ever claimed.
                assert_eq!(p.target_uid, None);
                assert_eq!(p.target_gid, None);
                assert_eq!(p.exe_path, "/usr/bin/sudo");
                assert_eq!(p.comm, "sudo");
                assert!(p.success);
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// A quoted `cmd="..."` (a short, space-free command) must be taken
    /// literally, not hex-decoded — the same quoted/unquoted distinction
    /// `osiris-sensors-fs` draws for `name=`/`cwd=`.
    #[test]
    fn a_quoted_command_is_not_hex_decoded() {
        let line = USER_CMD.replace(
            "cmd=2F7573722F62696E2F77686F616D69",
            r#"cmd="deadbeef""#,
        );
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.command.as_deref(), Some("deadbeef")),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// Some sudo/audit builds omit `exe=` from USER_CMD entirely. The
    /// result is an empty exe_path/comm — the same "unknown, not invented"
    /// convention the Network sensor uses for an unattributed socket — not
    /// a hard-coded `/usr/bin/sudo`.
    #[test]
    fn a_user_cmd_without_an_exe_field_reports_an_empty_path_rather_than_guessing() {
        let line = USER_CMD.replace(r#" exe="/usr/bin/sudo""#, "");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => {
                assert_eq!(p.exe_path, "");
                assert_eq!(p.comm, "");
            }
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    /// A `USER_CMD` with no `ses=` is still a real privilege event: unlike a
    /// session-lifecycle record it names something (a command run under
    /// sudo), so it is emitted with `session_id: None` rather than dropped.
    #[test]
    fn a_user_cmd_without_a_session_is_emitted_with_no_session_rather_than_dropped() {
        let line = USER_CMD.replace(" ses=3", "");
        match parse_record(&line).expect("must parse") {
            IdentityRecord::Privilege(p) => assert_eq!(p.session_id, None),
            other => panic!("expected a Privilege record, got {other:?}"),
        }
    }

    // --- Everything else in the log is not ours ---

    #[test]
    fn unrelated_record_types_are_ignored() {
        for line in [
            r#"type=PROCTITLE msg=audit(1690000000.123:456): proctitle=726D"#,
            r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/tmp/foo" nametype=CREATE"#,
            r#"type=CRED_ACQ msg=audit(1690000000.140:458): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:setcred acct="root" exe="/usr/sbin/sshd" res=success'"#,
            r#"type=CWD msg=audit(1690000000.123:456): cwd="/home/alice""#,
        ] {
            assert!(parse_record(line).is_none(), "must ignore: {line}");
        }
    }
}
