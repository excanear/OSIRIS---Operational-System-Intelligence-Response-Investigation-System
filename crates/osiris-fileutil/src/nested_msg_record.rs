use std::collections::HashMap;

use crate::{parse_audit_msg_id, tokenize, AuditMsgId};

/// auditd's `(unsigned)-1` sentinel, printed for an unset `auid=`/`ses=`
/// and for a `setuid`/`setgid` argument meaning "leave this id unchanged".
pub const UNSET_ID: &str = "4294967295";

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
            // Close on the LAST `'` in the remainder, not the first. Every
            // real auditd `USER_*` record puts the nested `msg='…'`
            // sub-record last, so its closing quote is the final `'` on the
            // line. Closing on the first `'` instead would let an embedded
            // quote inside an inner field (e.g. `acct="o'brien"`) truncate
            // the inner record early and splice the genuine remainder back
            // into the trusted `outer` layer, where a forged `ses=`/`uid=`/
            // `pid=` could shadow the real one via `tokenize`'s last-wins
            // `HashMap` semantics.
            match after.rfind('\'') {
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

/// auditd prints a literal `?` for an unknown `addr=`/`hostname=`/
/// `terminal=` — a local console login has no remote address. That is
/// "unknown", so it becomes `None`; `Some("?")` must never reach a
/// `SessionRef` (Phase 4a plan Global Constraint #9).
pub fn unknown_to_none(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "?" && *v != "(none)")
}

/// Parses a uid-like field, mapping auditd's unset sentinel to `None`
/// rather than to 4,294,967,295.
pub fn parse_id(value: Option<&str>) -> Option<u32> {
    value.filter(|v| *v != UNSET_ID)?.parse().ok()
}

/// A session id that can actually be correlated: present, non-empty, and
/// not the unset sentinel.
pub fn usable_session(value: Option<&str>) -> Option<String> {
    value
        .filter(|v| !v.is_empty() && *v != UNSET_ID && *v != "?")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_audit_msg_id, tokenize};

    // --- The seven record shapes this phase emits, in real auditd text ---

    /// `USER_LOGIN` reports the logging-in account as `id=<uid>` rather
    /// than `acct="name"` on most builds — hence `username: None` for this
    /// line, with `acct=` exercised on USER_START below.
    const USER_LOGIN: &str = r#"type=USER_LOGIN msg=audit(1690000000.123:456): pid=1200 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;
    const USER_START: &str = r#"type=USER_START msg=audit(1690000000.130:457): pid=1200 uid=0 auid=1000 ses=3 msg='op=PAM:session_open grantors=pam_selinux,pam_loginuid,pam_keyinit acct="alice" exe="/usr/sbin/sshd" hostname=198.51.100.10 addr=198.51.100.10 terminal=/dev/pts/0 res=success'"#;

    /// x86_64 syscall 105 is `setuid(2)`; `a0` is its single argument, in
    /// lowercase hex with no `0x` prefix — `a0=0` means "become uid 0".
    const SYSCALL_SETUID: &str = r#"type=SYSCALL msg=audit(1690000005.010:470): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=7ffd0e2b1c40 a2=0 a3=0 items=0 ppid=200 pid=300 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="osiris_identity""#;

    // --- The splitter: header / outer body / inner msg ---

    /// Global Constraint #9's load-bearing consequence, stated as a test: a
    /// `USER_*` line has TWO `msg=` fields, and `tokenize`'s `HashMap` keeps
    /// only the last one, so feeding such a line to `tokenize` whole
    /// destroys the audit header. `split_record` must not.
    #[test]
    fn a_whole_user_line_fed_to_tokenize_loses_the_header_but_split_record_does_not() {
        // Proof of the hazard, so this fails loudly if `tokenize`'s
        // contract ever changes underneath us.
        let naive = tokenize(USER_LOGIN);
        assert!(
            parse_audit_msg_id(naive.get("msg").unwrap()).is_none(),
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
}
