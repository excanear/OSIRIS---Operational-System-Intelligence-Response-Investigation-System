use std::time::{Duration, Instant};

use osiris_fileutil::AuditMsgId;
use osiris_sensor_api::{FileEventRaw, FileOperation, RawEventSource};

use crate::audit_record::{
    parse_record, syscall_class, AuditRecord, NameType, PathRecord, SyscallClass, SyscallRecord,
};

/// One kernel audit event's records, accumulated until the group closes.
struct PendingGroup {
    id: AuditMsgId,
    syscall: Option<SyscallRecord>,
    cwd: Option<String>,
    paths: Vec<PathRecord>,
    first_seen: Instant,
}

/// Groups an auditd log's records into complete kernel audit events and
/// turns each into zero or more `FileEventRaw`s.
///
/// auditd writes every record of one event contiguously, so exactly one
/// group is ever open: a record bearing a new `AuditMsgId` proves the
/// previous group is complete. The one case that rule cannot cover is the
/// *last* event in the file, which has no successor — that is what
/// `completion_timeout` and `tick` are for.
pub struct AuditEventAssembler {
    pending: Option<PendingGroup>,
    completion_timeout: Duration,
    /// Guards against a pathological log (a single event with an unbounded
    /// number of PATH records) growing this buffer without limit.
    max_paths_per_group: usize,
}

impl AuditEventAssembler {
    pub fn new(completion_timeout: Duration) -> Self {
        Self {
            pending: None,
            completion_timeout,
            max_paths_per_group: 64,
        }
    }

    /// Feeds one raw audit log line. Returns the file events of the
    /// *previous* group if this line closed it. Lines that don't parse are
    /// skipped without disturbing the open group.
    pub fn offer(&mut self, line: &str, now: Instant) -> Vec<FileEventRaw> {
        let Some((id, record)) = parse_record(line) else {
            return vec![];
        };
        let mut emitted = vec![];
        match &self.pending {
            Some(group) if group.id == id => {}
            Some(_) => emitted = self.take_pending(),
            None => {}
        }
        let group = self.pending.get_or_insert_with(|| PendingGroup {
            id,
            syscall: None,
            cwd: None,
            paths: Vec::new(),
            first_seen: now,
        });
        match record {
            AuditRecord::Syscall(s) => group.syscall = Some(s),
            AuditRecord::Cwd(cwd) => group.cwd = Some(cwd),
            AuditRecord::Path(p) => {
                if group.paths.len() < self.max_paths_per_group {
                    group.paths.push(p);
                }
            }
            AuditRecord::Other => {}
        }
        emitted
    }

    /// Releases the open group once it has gone `completion_timeout`
    /// without a new record — the only way the final event in a quiet log
    /// ever gets reported.
    pub fn tick(&mut self, now: Instant) -> Vec<FileEventRaw> {
        let expired = self
            .pending
            .as_ref()
            .map(|g| now.duration_since(g.first_seen) >= self.completion_timeout)
            .unwrap_or(false);
        if expired {
            self.take_pending()
        } else {
            vec![]
        }
    }

    /// Releases the open group unconditionally (shutdown, and tests).
    pub fn flush(&mut self) -> Vec<FileEventRaw> {
        self.take_pending()
    }

    fn take_pending(&mut self) -> Vec<FileEventRaw> {
        let Some(group) = self.pending.take() else {
            return vec![];
        };
        let Some(syscall) = &group.syscall else {
            // PATH records with no SYSCALL record describe nothing
            // attributable — no acting process, no syscall class.
            return vec![];
        };
        group_to_file_events(group.id, syscall, group.cwd.as_deref(), &group.paths)
    }
}

/// The pure joiner: one completed audit event group in, file events out.
/// Free-standing and clock-free so every correlation rule below is
/// testable without an `Instant`.
pub fn group_to_file_events(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    cwd: Option<&str>,
    paths: &[PathRecord],
) -> Vec<FileEventRaw> {
    // A syscall that failed changed nothing on disk.
    if !syscall.success {
        return vec![];
    }
    let Some(class) = syscall_class(syscall.syscall) else {
        return vec![];
    };
    // PARENT items are directories resolved on the way to the operand, not
    // operations in their own right; UNKNOWN items are unclassifiable.
    let operands: Vec<&PathRecord> = paths
        .iter()
        .filter(|p| !matches!(p.nametype, NameType::Parent | NameType::Unknown))
        .collect();
    if operands.is_empty() {
        return vec![];
    }

    if class == SyscallClass::Rename {
        return rename_event(id, syscall, cwd, &operands).into_iter().collect();
    }

    operands
        .iter()
        .filter_map(|path| {
            let operation = match path.nametype {
                NameType::Create => FileOperation::Create,
                NameType::Delete => FileOperation::Delete,
                // A merely-touched path counts as a write only when the
                // syscall could modify contents. Read-only opens produce
                // NORMAL items too, and this phase emits no read events
                // (§6's Filesystem STANDARD row).
                NameType::Normal if class == SyscallClass::Write => FileOperation::Write,
                _ => return None,
            };
            Some(build_event(id, syscall, operation, absolutize(&path.name, cwd), None, path))
        })
        .collect()
}

/// rename/renameat/renameat2 emit a DELETE for the source and a CREATE for
/// the destination (plus a second DELETE when the destination already
/// existed and was clobbered). That is ONE move, not a delete and a
/// create — and the moved file keeps the SOURCE's inode, so the source
/// item is what supplies the identity a File Story follows across the
/// rename.
fn rename_event(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    cwd: Option<&str>,
    operands: &[&PathRecord],
) -> Option<FileEventRaw> {
    let source = operands
        .iter()
        .find(|p| p.nametype == NameType::Delete)
        .copied()?;
    let destination = operands
        .iter()
        .find(|p| p.nametype == NameType::Create)
        .copied()
        // renameat2 with RENAME_EXCHANGE reports no CREATE item; fall back
        // to the last DELETE so the event still names both ends.
        .or_else(|| {
            operands
                .iter()
                .rev()
                .find(|p| p.nametype == NameType::Delete && !std::ptr::eq(**p, source))
                .copied()
        })?;
    Some(build_event(
        id,
        syscall,
        FileOperation::Rename,
        absolutize(&destination.name, cwd),
        Some(absolutize(&source.name, cwd)),
        source,
    ))
}

/// `identity_source` is the PATH record whose inode/device/mode describe
/// the file this event is *about* — the same record as the path for every
/// operation except rename, where it is the source item.
fn build_event(
    id: AuditMsgId,
    syscall: &SyscallRecord,
    operation: FileOperation,
    path: String,
    previous_path: Option<String>,
    identity_source: &PathRecord,
) -> FileEventRaw {
    FileEventRaw {
        operation,
        path,
        previous_path,
        inode: identity_source.inode,
        device_id: identity_source.device_id,
        mode: identity_source.mode,
        owner_uid: identity_source.owner_uid,
        owner_gid: identity_source.owner_gid,
        pid: syscall.pid,
        ppid: syscall.ppid,
        uid: syscall.uid,
        exe_path: syscall.exe_path.clone(),
        comm: syscall.comm.clone(),
        timestamp_ns: id.timestamp_ns,
        audit_serial: Some(id.serial),
        source: RawEventSource::Audit,
    }
}

/// The kernel prints `name=` exactly as the syscall received it, so a
/// relative path must be joined to the group's `type=CWD` record. A
/// relative path with no CWD record is returned unchanged rather than
/// guessed at — downstream it is still a real, if less useful, observation.
fn absolutize(name: &str, cwd: Option<&str>) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    match cwd {
        Some(cwd) => format!("{}/{}", cwd.trim_end_matches('/'), name),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::FileOperation;

    fn syscall_line(serial: u64, nr: u32, comm: &str, exe: &str) -> String {
        format!(
            r#"type=SYSCALL msg=audit(1690000000.123:{serial}): arch=c000003e syscall={nr} success=yes exit=0 items=2 ppid=200 pid=300 auid=1000 uid=1000 tty=pts0 ses=1 comm="{comm}" exe="{exe}" key="osiris_fs""#
        )
    }

    fn path_line(serial: u64, item: u32, name: &str, inode: u64, nametype: &str) -> String {
        format!(
            r#"type=PATH msg=audit(1690000000.123:{serial}): item={item} name="{name}" inode={inode} dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype={nametype}"#
        )
    }

    fn cwd_line(serial: u64, cwd: &str) -> String {
        format!(r#"type=CWD msg=audit(1690000000.123:{serial}): cwd="{cwd}""#)
    }

    /// The pure joiner, tested without any clock at all.
    fn events_for(lines: &[String]) -> Vec<osiris_sensor_api::FileEventRaw> {
        let mut assembler = AuditEventAssembler::new(Duration::from_millis(0));
        let start = Instant::now();
        let mut out = vec![];
        for line in lines {
            out.extend(assembler.offer(line, start));
        }
        out.extend(assembler.flush());
        out
    }

    #[test]
    fn unlink_produces_one_delete_event_and_ignores_the_parent_item() {
        let lines = vec![
            syscall_line(456, 87, "rm", "/usr/bin/rm"),
            cwd_line(456, "/home/user"),
            path_line(456, 0, "/tmp", 131074, "PARENT"),
            path_line(456, 1, "/tmp/foo", 131075, "DELETE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1, "PARENT items must never become events");
        let event = &events[0];
        assert_eq!(event.operation, FileOperation::Delete);
        assert_eq!(event.path, "/tmp/foo");
        assert_eq!(event.inode, Some(131075));
        assert_eq!(event.device_id, Some(osiris_schema::encode_device_id(8, 1)));
        assert_eq!(event.pid, 300);
        assert_eq!(event.ppid, 200);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.exe_path, "/usr/bin/rm");
        assert_eq!(event.comm, "rm");
        assert_eq!(event.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(event.audit_serial, Some(456));
    }

    #[test]
    fn open_with_o_creat_produces_a_create_event() {
        let lines = vec![
            syscall_line(457, 257, "curl", "/usr/bin/curl"),
            path_line(457, 0, "/var/www/html", 200000, "PARENT"),
            path_line(457, 1, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Create);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
    }

    #[test]
    fn opening_an_existing_file_for_write_produces_a_write_event() {
        let lines = vec![
            syscall_line(458, 257, "curl", "/usr/bin/curl"),
            path_line(458, 0, "/var/www/html/shell.php", 200001, "NORMAL"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Write);
    }

    /// A NORMAL path operand on a syscall that cannot modify contents is
    /// not a write. This phase emits no read events at all (§6's Filesystem
    /// STANDARD row), so such a group must produce nothing.
    #[test]
    fn a_normal_path_on_a_non_write_syscall_produces_nothing() {
        let lines = vec![
            // stat(2) = 4, not in any file-syscall class.
            syscall_line(459, 4, "ls", "/usr/bin/ls"),
            path_line(459, 0, "/var/www/html/shell.php", 200001, "NORMAL"),
        ];
        assert!(events_for(&lines).is_empty());
    }

    /// rename() emits PARENT, PARENT, DELETE(src), CREATE(dst). The two
    /// must join into exactly ONE FILE_RENAME, never a delete plus a create
    /// — and the identity must be the SOURCE's inode, because that is the
    /// inode the file keeps, and following it is the whole reason File
    /// Story joins on identity rather than path.
    #[test]
    fn rename_joins_the_delete_and_create_items_into_one_event() {
        let lines = vec![
            syscall_line(460, 82, "curl", "/usr/bin/curl"),
            path_line(460, 0, "/var/www/html", 200000, "PARENT"),
            path_line(460, 1, "/var/www/html", 200000, "PARENT"),
            path_line(460, 2, "/var/www/html/.shell.php.tmp", 200001, "DELETE"),
            path_line(460, 3, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.operation, FileOperation::Rename);
        assert_eq!(event.path, "/var/www/html/shell.php");
        assert_eq!(
            event.previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
        assert_eq!(event.inode, Some(200001));
    }

    /// Renaming *over* an existing file emits a second DELETE for the
    /// destination. The event is still one rename, and its identity is
    /// still the source's (the first DELETE item's) inode — not the
    /// clobbered destination's.
    #[test]
    fn rename_over_an_existing_destination_is_still_one_event_with_the_source_inode() {
        let lines = vec![
            syscall_line(461, 82, "curl", "/usr/bin/curl"),
            path_line(461, 0, "/var/www/html", 200000, "PARENT"),
            path_line(461, 1, "/var/www/html", 200000, "PARENT"),
            path_line(461, 2, "/var/www/html/.shell.php.tmp", 200001, "DELETE"),
            path_line(461, 3, "/var/www/html/shell.php", 199999, "DELETE"),
            path_line(461, 4, "/var/www/html/shell.php", 200001, "CREATE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, FileOperation::Rename);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
        assert_eq!(
            events[0].previous_path.as_deref(),
            Some("/var/www/html/.shell.php.tmp")
        );
        assert_eq!(events[0].inode, Some(200001));
    }

    #[test]
    fn a_relative_path_is_absolutized_against_the_groups_cwd_record() {
        let lines = vec![
            syscall_line(462, 87, "rm", "/usr/bin/rm"),
            cwd_line(462, "/var/www/html"),
            path_line(462, 0, "shell.php", 200001, "DELETE"),
        ];
        let events = events_for(&lines);
        assert_eq!(events[0].path, "/var/www/html/shell.php");
    }

    #[test]
    fn a_failed_syscall_produces_no_events() {
        let failed = syscall_line(463, 87, "rm", "/usr/bin/rm").replace("success=yes", "success=no");
        let lines = vec![failed, path_line(463, 0, "/tmp/foo", 131075, "DELETE")];
        assert!(events_for(&lines).is_empty());
    }

    #[test]
    fn a_group_with_no_syscall_record_produces_no_events() {
        let lines = vec![path_line(464, 0, "/tmp/foo", 131075, "DELETE")];
        assert!(events_for(&lines).is_empty());
    }

    /// Two consecutive audit events must not bleed into each other: the
    /// arrival of a record with a new id closes the previous group.
    #[test]
    fn a_new_event_id_closes_the_previous_group() {
        let mut assembler = AuditEventAssembler::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(assembler
            .offer(&syscall_line(470, 87, "rm", "/usr/bin/rm"), now)
            .is_empty());
        assert!(assembler
            .offer(&path_line(470, 0, "/tmp/a", 1, "DELETE"), now)
            .is_empty());
        // The first record of event 471 closes event 470.
        let emitted = assembler.offer(&syscall_line(471, 87, "rm", "/usr/bin/rm"), now);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/a");
        assert_eq!(emitted[0].audit_serial, Some(470));
    }

    /// The final event in a log file has no following record to close it,
    /// so a pending group must be released once it has sat untouched for
    /// the completion timeout. Without this the last file operation before
    /// the system goes quiet is never reported.
    #[test]
    fn a_pending_group_is_released_by_tick_after_the_completion_timeout() {
        let mut assembler = AuditEventAssembler::new(Duration::from_millis(100));
        let start = Instant::now();
        assembler.offer(&syscall_line(480, 87, "rm", "/usr/bin/rm"), start);
        assembler.offer(&path_line(480, 0, "/tmp/last", 1, "DELETE"), start);

        assert!(
            assembler.tick(start + Duration::from_millis(50)).is_empty(),
            "must not release a group that could still be receiving records"
        );
        let emitted = assembler.tick(start + Duration::from_millis(150));
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/last");
        // Released once and once only.
        assert!(assembler.tick(start + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn unparseable_lines_are_skipped_without_disturbing_the_open_group() {
        let mut assembler = AuditEventAssembler::new(Duration::from_secs(60));
        let now = Instant::now();
        assembler.offer(&syscall_line(490, 87, "rm", "/usr/bin/rm"), now);
        assert!(assembler.offer("garbage with no audit header", now).is_empty());
        assembler.offer(&path_line(490, 0, "/tmp/foo", 1, "DELETE"), now);
        let emitted = assembler.flush();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].path, "/tmp/foo");
    }
}
