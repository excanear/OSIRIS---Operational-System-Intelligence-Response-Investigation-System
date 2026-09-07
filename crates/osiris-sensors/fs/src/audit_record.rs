use osiris_fileutil::{parse_audit_msg_id, tokenize, AuditMsgId};
use osiris_schema::encode_device_id;

/// The `nametype` field of a `type=PATH` record — the kernel's own
/// statement of what role the path played in the syscall. This, not the
/// syscall number alone, is what tells create from delete from touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    /// A containing directory, resolved on the way to the real operand.
    /// Never an event in its own right.
    Parent,
    /// A path the syscall touched without creating or removing its dentry.
    Normal,
    Create,
    Delete,
    /// The kernel could not classify it, or emitted a value this build does
    /// not know. Treated as "not an event" rather than guessed at.
    Unknown,
}

/// The classes of file syscall this phase handles, keyed by x86_64 syscall
/// number. `write(2)` is deliberately absent: it operates on a file
/// descriptor and emits no `type=PATH` records, so there is nothing to
/// correlate — the `open`/`openat` that produced the descriptor is what
/// audit reports, and that is what this sensor keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallClass {
    /// open/openat/openat2/creat/truncate/ftruncate — a NORMAL path operand
    /// here means the file's contents were opened for modification.
    Write,
    /// mkdir/mkdirat.
    Create,
    /// unlink/unlinkat/rmdir.
    Delete,
    /// rename/renameat/renameat2 — the one class producing a paired
    /// DELETE + CREATE that must be joined into a single event.
    Rename,
}

pub fn syscall_class(nr: u32) -> Option<SyscallClass> {
    match nr {
        2 | 257 | 437 | 85 | 76 | 77 => Some(SyscallClass::Write),
        83 | 258 => Some(SyscallClass::Create),
        87 | 263 | 84 => Some(SyscallClass::Delete),
        82 | 264 | 316 => Some(SyscallClass::Rename),
        _ => None,
    }
}

pub fn is_file_syscall(nr: u32) -> bool {
    syscall_class(nr).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallRecord {
    pub syscall: u32,
    pub success: bool,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe_path: String,
    /// The audit rule's `-F key=` tag, when the rule set one. Lets the
    /// sensor consume only the records its own watch rules produced.
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRecord {
    pub item: u32,
    /// As printed by the kernel — may be relative, in which case the
    /// group's `type=CWD` record absolutizes it (see `assembler`).
    pub name: String,
    pub inode: Option<u64>,
    pub device_id: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub nametype: NameType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    Syscall(SyscallRecord),
    Path(PathRecord),
    Cwd(String),
    /// Any other record type sharing the event id (PROCTITLE, EXECVE, ...).
    /// Kept rather than dropped so the assembler can see that the group is
    /// still open.
    Other,
}

/// Parses one auditd log line into its shared event id plus its payload.
/// Returns `None` only for lines with no parseable `msg=audit(...)` header
/// or a PATH record with no usable name — never panics on malformed input.
pub fn parse_record(line: &str) -> Option<(AuditMsgId, AuditRecord)> {
    let fields = tokenize(line);
    let id = parse_audit_msg_id(fields.get("msg")?)?;
    let record = match fields.get("type").map(String::as_str) {
        Some("SYSCALL") => AuditRecord::Syscall(SyscallRecord {
            syscall: fields.get("syscall")?.parse().ok()?,
            success: fields.get("success").map(String::as_str) == Some("yes"),
            pid: fields.get("pid")?.parse().ok()?,
            ppid: fields.get("ppid")?.parse().ok()?,
            uid: fields.get("uid")?.parse().ok()?,
            comm: fields.get("comm").cloned().unwrap_or_default(),
            exe_path: fields.get("exe").cloned().unwrap_or_default(),
            key: fields
                .get("key")
                .filter(|k| k.as_str() != "(null)")
                .cloned(),
        }),
        Some("PATH") => {
            let name = decode_untrusted_string(line, "name", fields.get("name")?);
            if name.is_empty() || name == "(null)" {
                return None;
            }
            AuditRecord::Path(PathRecord {
                item: fields.get("item").and_then(|v| v.parse().ok()).unwrap_or(0),
                name,
                inode: fields.get("inode").and_then(|v| v.parse().ok()),
                device_id: fields.get("dev").and_then(|v| parse_dev(v)),
                mode: fields
                    .get("mode")
                    .and_then(|v| u32::from_str_radix(v, 8).ok()),
                owner_uid: fields.get("ouid").and_then(|v| v.parse().ok()),
                owner_gid: fields.get("ogid").and_then(|v| v.parse().ok()),
                nametype: parse_nametype(fields.get("nametype").map(String::as_str)),
            })
        }
        Some("CWD") => AuditRecord::Cwd(decode_untrusted_string(line, "cwd", fields.get("cwd")?)),
        _ => AuditRecord::Other,
    };
    Some((id, record))
}

fn parse_nametype(raw: Option<&str>) -> NameType {
    match raw {
        Some("PARENT") => NameType::Parent,
        Some("NORMAL") => NameType::Normal,
        Some("CREATE") => NameType::Create,
        Some("DELETE") => NameType::Delete,
        // Includes the kernel's literal "UNKNOWN" and any value a future
        // kernel adds: unrecognised is never guessed at.
        _ => NameType::Unknown,
    }
}

/// The kernel logs a string via `audit_log_untrustedstring`: any value
/// containing a byte outside printable-ASCII-minus-quote (`0x21..=0x7e`,
/// excluding `"`) — a space, control character, or embedded quote — comes
/// out **unquoted, as uppercase hex** instead of the usual `key="value"`
/// form. `name=` and `cwd=` (paths) are exactly the fields this sensor
/// reads that carry attacker- or user-controlled bytes, so a filename with
/// a space (`shell copy.php`) is logged as
/// `name=7368656C6C20636F70792E706870`, not `name="shell copy.php"`.
/// Passing that hex blob straight through would silently corrupt every
/// such path rather than failing loudly, so it is decoded here before
/// `FileEventRaw.path`/`previous_path` are ever built.
///
/// `tokenize` already strips quotes from a quoted value, so the
/// quoted/unquoted distinction can't be read back off its output — a
/// legitimately quoted, all-hex-digit name (`name="deadbeef"`, a real if
/// unusual filename) must not be mistaken for an encoded one. This checks
/// the raw line for the literal `key="` marker instead of guessing from
/// the value's shape.
fn decode_untrusted_string(line: &str, key: &str, raw_value: &str) -> String {
    if line.contains(&format!("{key}=\"")) {
        return raw_value.to_string();
    }
    decode_hex(raw_value).unwrap_or_else(|| raw_value.to_string())
}

/// Hex-decodes an unquoted `audit_log_untrustedstring` value. Returns
/// `None` for anything that isn't a well-formed even-length hex string —
/// including the ordinary case of a short unquoted token like `(null)` —
/// so the caller falls back to the raw value unchanged rather than
/// mangling it.
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

/// Decodes an audit PATH record's `dev=MAJ:MIN` field. Both halves are
/// **hexadecimal** (`dev=08:01` is major 8 minor 1; `dev=fd:00` is major
/// 253) — reading them as decimal silently mis-identifies every LVM and
/// device-mapper volume.
fn parse_dev(raw: &str) -> Option<u64> {
    let (major, minor) = raw.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some(encode_device_id(major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_UNLINK: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=87 success=yes exit=0 a0=7ffd items=2 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="rm" exe="/usr/bin/rm" subj=unconfined key="osiris_fs""#;
    const CWD_LINE: &str = r#"type=CWD msg=audit(1690000000.123:456): cwd="/home/user""#;
    const PATH_PARENT: &str = r#"type=PATH msg=audit(1690000000.123:456): item=0 name="/tmp" inode=131074 dev=08:01 mode=040777 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0"#;
    const PATH_DELETE: &str = r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/tmp/foo" inode=131075 dev=08:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0"#;

    #[test]
    fn parses_a_syscall_record_with_the_acting_process() {
        let (id, record) = parse_record(SYSCALL_UNLINK).expect("must parse");
        assert_eq!(id.serial, 456);
        assert_eq!(id.timestamp_ns, 1_690_000_000_123_000_000);
        match record {
            AuditRecord::Syscall(s) => {
                assert_eq!(s.syscall, 87);
                assert!(s.success);
                assert_eq!(s.pid, 300);
                assert_eq!(s.ppid, 200);
                assert_eq!(s.uid, 1000);
                assert_eq!(s.comm, "rm");
                assert_eq!(s.exe_path, "/usr/bin/rm");
                assert_eq!(s.key.as_deref(), Some("osiris_fs"));
            }
            other => panic!("expected Syscall, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_path_record_decoding_hex_dev_and_octal_mode() {
        let (_, record) = parse_record(PATH_DELETE).expect("must parse");
        match record {
            AuditRecord::Path(p) => {
                assert_eq!(p.item, 1);
                assert_eq!(p.name, "/tmp/foo");
                assert_eq!(p.inode, Some(131075));
                // dev=08:01 is HEX major:minor -> major 8, minor 1.
                assert_eq!(p.device_id, Some(osiris_schema::encode_device_id(8, 1)));
                // mode=0100644 is OCTAL: regular file, rw-r--r--.
                assert_eq!(p.mode, Some(0o100644));
                assert_eq!(p.owner_uid, Some(1000));
                assert_eq!(p.owner_gid, Some(1000));
                assert_eq!(p.nametype, NameType::Delete);
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    /// A hex dev field with letters must not be read as decimal: `dev=fd:00`
    /// is major 253 (an LVM device), not a parse failure and not 65,536.
    #[test]
    fn decodes_a_hex_dev_field_containing_letters() {
        let line = PATH_DELETE.replace("dev=08:01", "dev=fd:00");
        let (_, record) = parse_record(&line).expect("must parse");
        match record {
            AuditRecord::Path(p) => {
                assert_eq!(p.device_id, Some(osiris_schema::encode_device_id(253, 0)))
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    /// The kernel does not quote a name containing a space (or any other
    /// byte outside printable-ASCII-minus-quote); it logs it unquoted, as
    /// uppercase hex instead: `audit_log_untrustedstring` on
    /// `/var/www/html/shell 2.php` yields
    /// `name=2F7661722F7777772F68746D6C2F7368656C6C20322E706870`. That must
    /// decode back to the real path, not flow into `FileEventRaw.path` as
    /// an unmatchable hex blob.
    #[test]
    fn decodes_a_hex_encoded_name_containing_a_space() {
        let line = PATH_DELETE.replace(
            r#"name="/tmp/foo""#,
            "name=2F7661722F7777772F68746D6C2F7368656C6C20322E706870",
        );
        match parse_record(&line).expect("must parse").1 {
            AuditRecord::Path(p) => assert_eq!(p.name, "/var/www/html/shell 2.php"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    /// Same encoding applies to `type=CWD`'s `cwd=` field.
    #[test]
    fn decodes_a_hex_encoded_cwd_containing_a_space() {
        let line = CWD_LINE.replace(r#"cwd="/home/user""#, "cwd=2F686F6D652F7573206572");
        match parse_record(&line).expect("must parse").1 {
            AuditRecord::Cwd(cwd) => assert_eq!(cwd, "/home/us er"),
            other => panic!("expected Cwd, got {other:?}"),
        }
    }

    /// A legitimately quoted, all-hex-digit name must not be mistaken for
    /// an encoded one just because its characters happen to all be hex
    /// digits — the quoted form is never hex-encoded by the kernel.
    #[test]
    fn a_quoted_all_hex_digit_name_is_left_alone() {
        let line = PATH_DELETE.replace(r#"name="/tmp/foo""#, r#"name="deadbeef""#);
        match parse_record(&line).expect("must parse").1 {
            AuditRecord::Path(p) => assert_eq!(p.name, "deadbeef"),
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn parses_every_nametype_the_kernel_emits() {
        for (raw, expected) in [
            ("PARENT", NameType::Parent),
            ("NORMAL", NameType::Normal),
            ("CREATE", NameType::Create),
            ("DELETE", NameType::Delete),
            ("UNKNOWN", NameType::Unknown),
            ("SOMETHING_NEW", NameType::Unknown),
        ] {
            let line = PATH_DELETE.replace("nametype=DELETE", &format!("nametype={raw}"));
            match parse_record(&line).expect("must parse").1 {
                AuditRecord::Path(p) => assert_eq!(p.nametype, expected, "{raw}"),
                other => panic!("expected Path, got {other:?}"),
            }
        }
    }

    #[test]
    fn parses_a_cwd_record() {
        match parse_record(CWD_LINE).expect("must parse").1 {
            AuditRecord::Cwd(cwd) => assert_eq!(cwd, "/home/user"),
            other => panic!("expected Cwd, got {other:?}"),
        }
    }

    #[test]
    fn classifies_unrelated_record_types_as_other_rather_than_dropping_them() {
        // PROCTITLE shares the event's id, so it must still parse (the
        // assembler needs the id to know the group hasn't ended) but carry
        // no payload.
        let line = r#"type=PROCTITLE msg=audit(1690000000.123:456): proctitle=726D"#;
        let (id, record) = parse_record(line).expect("must parse");
        assert_eq!(id.serial, 456);
        assert!(matches!(record, AuditRecord::Other));
    }

    #[test]
    fn rejects_a_line_with_no_audit_header() {
        assert!(parse_record("this is not an audit record").is_none());
    }

    #[test]
    fn a_path_record_with_a_null_name_is_rejected() {
        let line = PATH_DELETE.replace(r#"name="/tmp/foo""#, "name=(null)");
        assert!(parse_record(&line).is_none());
    }

    #[test]
    fn a_parent_path_record_still_parses_so_the_assembler_can_ignore_it_by_nametype() {
        match parse_record(PATH_PARENT).expect("must parse").1 {
            AuditRecord::Path(p) => {
                assert_eq!(p.item, 0);
                assert_eq!(p.nametype, NameType::Parent);
            }
            other => panic!("expected Path, got {other:?}"),
        }
    }

    #[test]
    fn classifies_the_file_syscalls_this_phase_handles() {
        assert_eq!(syscall_class(87), Some(SyscallClass::Delete)); // unlink
        assert_eq!(syscall_class(263), Some(SyscallClass::Delete)); // unlinkat
        assert_eq!(syscall_class(84), Some(SyscallClass::Delete)); // rmdir
        assert_eq!(syscall_class(82), Some(SyscallClass::Rename)); // rename
        assert_eq!(syscall_class(264), Some(SyscallClass::Rename)); // renameat
        assert_eq!(syscall_class(316), Some(SyscallClass::Rename)); // renameat2
        assert_eq!(syscall_class(83), Some(SyscallClass::Create)); // mkdir
        assert_eq!(syscall_class(258), Some(SyscallClass::Create)); // mkdirat
        assert_eq!(syscall_class(2), Some(SyscallClass::Write)); // open
        assert_eq!(syscall_class(257), Some(SyscallClass::Write)); // openat
        assert_eq!(syscall_class(437), Some(SyscallClass::Write)); // openat2
        assert_eq!(syscall_class(85), Some(SyscallClass::Write)); // creat
        assert_eq!(syscall_class(76), Some(SyscallClass::Write)); // truncate
        assert_eq!(syscall_class(77), Some(SyscallClass::Write)); // ftruncate
        // execve is a Process/Exec concern, not a filesystem one, and
        // write(2) operates on an fd so it emits no PATH records at all.
        assert_eq!(syscall_class(59), None);
        assert_eq!(syscall_class(1), None);
        assert!(is_file_syscall(87));
        assert!(!is_file_syscall(59));
    }
}
