use std::time::{Duration, Instant};

use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
use osiris_sensor_api::ProcessExecRaw;

use crate::audit_line::exec_from_syscall_fields;
use crate::execve::ArgvCollector;

/// One execve audit event, open until its argv is complete or the group
/// closes.
struct PendingExec {
    id: AuditMsgId,
    exec: ProcessExecRaw,
    argv: ArgvCollector,
    /// Refreshed by every record of this event, so `tick` measures idle
    /// time since the group's last record (same rule as the Filesystem
    /// sensor's assembler).
    last_seen: Instant,
}

/// Joins an execve `SYSCALL` record with the `EXECVE` record(s) of the
/// same kernel audit event (same `msg=audit(...:<serial>)`) so the emitted
/// `ProcessExecRaw` carries argv.
///
/// auditd writes one event's records contiguously, so at most one exec is
/// open at a time. It is released:
/// - as soon as its argv is complete (the usual case: right after the
///   EXECVE record, without waiting for CWD/PATH/PROCTITLE);
/// - when a record with another serial arrives (a SYSCALL with no EXECVE
///   record is still reported, with an empty `cmdline`);
/// - by `tick` once it has been idle for `completion_timeout` (the last
///   event in a quiet log), or by `flush` on shutdown.
pub struct ExecAssembler {
    pending: Option<PendingExec>,
    completion_timeout: Duration,
}

impl ExecAssembler {
    pub fn new(completion_timeout: Duration) -> Self {
        Self {
            pending: None,
            completion_timeout,
        }
    }

    /// Feeds one raw audit log line; returns the execs this line released.
    /// Lines without a parseable `msg=audit(...)` header are skipped.
    pub fn offer(&mut self, line: &str, now: Instant) -> Vec<ProcessExecRaw> {
        let fields = tokenize(line);
        let Some(id) = fields.get("msg").and_then(|m| parse_audit_msg_id(m)) else {
            return vec![];
        };
        let mut released = vec![];
        if self.pending.as_ref().is_some_and(|p| p.id != id) {
            released.extend(self.take_pending());
        }
        match fields.get("type").map(String::as_str) {
            Some("SYSCALL") => {
                if let Some(exec) = exec_from_syscall_fields(&fields) {
                    self.pending = Some(PendingExec {
                        id,
                        exec,
                        argv: ArgvCollector::default(),
                        last_seen: now,
                    });
                }
            }
            Some(record_type) => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.last_seen = now;
                    if record_type == "EXECVE" {
                        pending.argv.feed(line);
                        if pending.argv.is_complete() {
                            released.extend(self.take_pending());
                        }
                    }
                }
            }
            None => {}
        }
        released
    }

    /// Releases the open exec once it has been idle for
    /// `completion_timeout`.
    pub fn tick(&mut self, now: Instant) -> Option<ProcessExecRaw> {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|p| now.duration_since(p.last_seen) >= self.completion_timeout);
        if expired {
            self.take_pending()
        } else {
            None
        }
    }

    /// Releases the open exec unconditionally (shutdown, and tests).
    pub fn flush(&mut self) -> Option<ProcessExecRaw> {
        self.take_pending()
    }

    fn take_pending(&mut self) -> Option<ProcessExecRaw> {
        let pending = self.pending.take()?;
        Some(ProcessExecRaw {
            cmdline: pending.argv.into_argv(),
            ..pending.exec
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 uid=1000 comm="curl" exe="/usr/bin/curl" key="osiris_exec""#;
    const EXECVE: &str =
        r#"type=EXECVE msg=audit(1690000000.123:456): argc=2 a0="curl" a1="https://example.com""#;
    const CWD: &str = r#"type=CWD msg=audit(1690000000.123:456): cwd="/root""#;
    const NEXT_EVENT: &str = r#"type=SYSCALL msg=audit(1690000000.200:457): arch=c000003e syscall=257 success=yes exit=3 ppid=1 pid=2 uid=0 comm="x" exe="/x""#;

    fn asm() -> ExecAssembler {
        ExecAssembler::new(Duration::from_millis(500))
    }

    #[test]
    fn releases_as_soon_as_the_execve_record_completes_argv() {
        let mut a = asm();
        let now = Instant::now();
        assert!(a.offer(SYSCALL, now).is_empty());
        let out = a.offer(EXECVE, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 5678);
        assert_eq!(out[0].cmdline, ["curl", "https://example.com"]);
        // Trailing records of the same event change nothing.
        assert!(a.offer(CWD, now).is_empty());
        assert!(a.flush().is_none());
    }

    #[test]
    fn a_syscall_without_execve_is_released_by_the_next_serial() {
        let mut a = asm();
        let now = Instant::now();
        assert!(a.offer(SYSCALL, now).is_empty());
        assert!(a.offer(CWD, now).is_empty());
        let out = a.offer(NEXT_EVENT, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].exe_path, "/usr/bin/curl");
        assert!(out[0].cmdline.is_empty());
    }

    #[test]
    fn tick_releases_an_idle_exec_only_after_the_timeout() {
        let mut a = asm();
        let t0 = Instant::now();
        a.offer(SYSCALL, t0);
        assert!(a.tick(t0 + Duration::from_millis(100)).is_none());
        let out = a
            .tick(t0 + Duration::from_millis(500))
            .expect("idle exec released");
        assert!(out.cmdline.is_empty());
        assert!(a.tick(t0 + Duration::from_secs(5)).is_none());
    }

    #[test]
    fn an_execve_record_of_another_event_is_not_attached() {
        let mut a = asm();
        let now = Instant::now();
        a.offer(SYSCALL, now);
        let foreign = EXECVE.replace(":456)", ":999)");
        let out = a.offer(&foreign, now);
        assert_eq!(out.len(), 1, "the new serial closes the open exec");
        assert!(out[0].cmdline.is_empty());
        assert!(a.flush().is_none(), "a lone EXECVE opens nothing");
    }

    #[test]
    fn non_exec_syscalls_and_unparseable_lines_emit_nothing() {
        let mut a = asm();
        let now = Instant::now();
        assert!(a.offer(NEXT_EVENT, now).is_empty());
        assert!(a.offer("garbage", now).is_empty());
        assert!(a.flush().is_none());
    }
}
