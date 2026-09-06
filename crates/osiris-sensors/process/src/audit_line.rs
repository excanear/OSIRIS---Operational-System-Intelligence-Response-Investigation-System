use osiris_fileutil::{parse_audit_msg_id, tokenize};
use osiris_sensor_api::{ProcessExecRaw, RawEventSource};

/// execve/execveat syscall numbers on x86_64 — the only syscalls this
/// parser extracts at MINIMAL telemetry (ARCHITECTURE.md §6's Process/Exec
/// MINIMAL row: "create/exit, pid/ppid/uid/exe", no argv).
const EXECVE_SYSCALL: &str = "59";
const EXECVEAT_SYSCALL: &str = "322";

/// Parses one `type=SYSCALL ...` line from a Linux audit log
/// (auditd-style, e.g. `/var/log/audit/audit.log`) into a ProcessExecRaw.
/// Returns None for any line that isn't a SYSCALL record for execve(at),
/// or that's missing a required field.
pub fn parse_audit_line(line: &str) -> Option<ProcessExecRaw> {
    let fields = tokenize(line);
    if fields.get("type").map(String::as_str) != Some("SYSCALL") {
        return None;
    }
    let syscall = fields.get("syscall")?;
    if syscall != EXECVE_SYSCALL && syscall != EXECVEAT_SYSCALL {
        return None;
    }
    let pid: u32 = fields.get("pid")?.parse().ok()?;
    let ppid: u32 = fields.get("ppid")?.parse().ok()?;
    let uid: u32 = fields.get("uid")?.parse().ok()?;
    let comm = fields.get("comm")?.clone();
    let exe_path = fields.get("exe")?.clone();
    let timestamp_ns = fields
        .get("msg")
        .and_then(|m| parse_audit_msg_id(m))
        .map(|id| id.timestamp_ns)
        .unwrap_or(0);

    Some(ProcessExecRaw {
        pid,
        ppid,
        uid,
        exe_path,
        comm,
        timestamp_ns,
        start_time_mono: timestamp_ns,
        source: RawEventSource::Audit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SYSCALL_LINE: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a1 a1=0 a2=0 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" subj=unconfined key=(null)"#;

    #[test]
    fn parses_a_real_execve_syscall_line() {
        let raw = parse_audit_line(SAMPLE_SYSCALL_LINE).expect("should parse");
        assert_eq!(raw.pid, 5678);
        assert_eq!(raw.ppid, 1234);
        assert_eq!(raw.uid, 1000);
        assert_eq!(raw.comm, "curl");
        assert_eq!(raw.exe_path, "/usr/bin/curl");
        assert_eq!(raw.timestamp_ns, 1_690_000_000_123_000_000);
    }

    #[test]
    fn ignores_non_syscall_lines() {
        let line = r#"type=EXECVE msg=audit(1690000000.123:456): argc=2 a0="curl" a1="https://example.com""#;
        assert!(parse_audit_line(line).is_none());
    }

    #[test]
    fn ignores_syscalls_that_are_not_execve() {
        let line = SAMPLE_SYSCALL_LINE.replace("syscall=59", "syscall=1");
        assert!(parse_audit_line(&line).is_none());
    }

    #[test]
    fn returns_none_when_required_field_missing() {
        let line = SAMPLE_SYSCALL_LINE.replace("exe=\"/usr/bin/curl\" ", "");
        assert!(parse_audit_line(&line).is_none());
    }

    #[test]
    fn returns_none_for_a_truncated_key_with_no_value() {
        // A line cut off mid-token: `pid=` with nothing after it (e.g. the
        // audit daemon's write got clipped by a crash or a partial tail
        // read landing exactly on a field boundary). tokenize() still
        // produces a "pid" key mapped to an empty string, so this must
        // fail cleanly at the `u32` parse (`?` short-circuits to None)
        // rather than panicking.
        let line = SAMPLE_SYSCALL_LINE.replace("pid=5678", "pid=");
        assert!(parse_audit_line(&line).is_none());
    }

    #[test]
    fn returns_none_for_an_unterminated_quote() {
        // A line cut off mid-quoted-value: `comm="curl` with no closing
        // `"`. tokenize()'s in_quotes flag never flips back off, so every
        // remaining field on the line (including `exe=`) gets swallowed
        // into the "comm" token's value instead of being parsed as its
        // own key=value pair. The required `exe` field is then missing,
        // so this must fail cleanly via `?` rather than panicking or
        // producing a garbage exe_path.
        let line =
            SAMPLE_SYSCALL_LINE.replace(r#"comm="curl" exe="/usr/bin/curl""#, r#"comm="curl"#);
        assert!(parse_audit_line(&line).is_none());
    }
}
