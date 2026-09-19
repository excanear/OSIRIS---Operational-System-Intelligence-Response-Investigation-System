use std::collections::HashMap;

/// The header every record of one audit event repeats:
/// `msg=audit(<secs>.<millis>:<serial>)`. Records sharing a `serial` (and
/// timestamp) belong to the same kernel audit event — for a file syscall
/// that means one `type=SYSCALL` record plus one `type=PATH` record per
/// path operand, plus an optional `type=CWD` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditMsgId {
    /// Nanoseconds since the epoch, derived from the header's
    /// `<secs>.<millis>` pair (auditd's own resolution is milliseconds).
    pub timestamp_ns: u64,
    pub serial: u64,
}

/// Tokenizes one auditd record line into `key=value` pairs, honoring
/// auditd's double-quoting convention for values that may contain spaces
/// (`comm="curl"`, `exe="/usr/bin/curl"`).
///
/// Malformed input is handled by producing something a caller can reject,
/// never by panicking: a truncated `pid=` yields an empty value (which
/// fails the caller's `parse()`), and an unterminated quote swallows the
/// rest of the line into that one value (so the caller's required fields
/// come back missing).
///
/// This function only tokenizes — it does not know or care whether a value
/// is real quoted text. In practice the kernel's `audit_log_untrustedstring`
/// helper only ever *quotes* a string when every byte in it is printable
/// ASCII other than `"` (`0x21..=0x7e` minus the quote); a string containing
/// a space, control character, or embedded quote (a filename with a space
/// in it, say) is logged **unquoted, as uppercase hex** instead — e.g.
/// `name=2F746D702F666F6F20626172` rather than `name="/tmp/foo bar"`. This
/// tokenizer does not hex-decode such values (it has no way to know which
/// fields might need it, and some callers — a raw `key=` audit rule tag,
/// say — never do); that decoding is the caller's job for whichever fields
/// carry untrusted strings (see `osiris_sensors_fs::audit_record::
/// parse_record`'s handling of `name=`/`cwd=`).
pub fn tokenize(line: &str) -> HashMap<String, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
        .into_iter()
        .filter_map(|t| {
            let mut parts = t.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").trim_matches('"').to_string();
            Some((key, value))
        })
        .collect()
}

/// Parses a `msg` field's `audit(1690000000.123:456)` payload. Accepts the
/// value with or without auditd's trailing `:` (the tokenizer strips the
/// record's trailing colon into the value in some layouts).
pub fn parse_audit_msg_id(msg: &str) -> Option<AuditMsgId> {
    let inner = msg.strip_prefix("audit(")?;
    let inner = inner.split(')').next()?;
    let (ts_part, serial_part) = inner.split_once(':')?;
    let (secs, millis) = ts_part.split_once('.')?;
    let secs: u64 = secs.parse().ok()?;
    let millis: u64 = millis.parse().ok()?;
    let serial: u64 = serial_part.parse().ok()?;
    Some(AuditMsgId {
        timestamp_ns: secs * 1_000_000_000 + millis * 1_000_000,
        serial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL_LINE: &str = r#"type=SYSCALL msg=audit(1690000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 uid=1000 comm="curl" exe="/usr/bin/curl" key=(null)"#;

    #[test]
    fn tokenizes_key_value_pairs_honouring_quoted_values() {
        let fields = tokenize(SYSCALL_LINE);
        assert_eq!(fields.get("type").map(String::as_str), Some("SYSCALL"));
        assert_eq!(fields.get("syscall").map(String::as_str), Some("59"));
        assert_eq!(fields.get("comm").map(String::as_str), Some("curl"));
        assert_eq!(fields.get("exe").map(String::as_str), Some("/usr/bin/curl"));
    }

    /// Exercises the tokenizer's generic quote-handling mechanic — some
    /// fields (`comm=`, `exe=`, `key=`) are legitimately quoted and may
    /// contain no bytes needing escaping. This is NOT how the kernel emits
    /// a `name=`/`cwd=` path containing a space: `audit_log_untrustedstring`
    /// only quotes a value when every byte is printable ASCII other than
    /// `"`; a space makes it log unquoted, uppercase hex instead (see
    /// `tokenize`'s doc comment). Decoding that hex form is exercised in
    /// `osiris_sensors_fs::audit_record`'s tests, not here.
    #[test]
    fn tokenizes_a_quoted_value_containing_spaces_as_one_token() {
        let fields = tokenize(r#"type=SYSCALL comm="my command" nametype=CREATE"#);
        assert_eq!(fields.get("comm").map(String::as_str), Some("my command"));
        assert_eq!(fields.get("nametype").map(String::as_str), Some("CREATE"));
    }

    /// The tokenizer itself does no hex-decoding — an unquoted
    /// `audit_log_untrustedstring` value (uppercase hex for
    /// `/tmp/foo bar`) comes back exactly as printed, for the caller to
    /// decode.
    #[test]
    fn does_not_hex_decode_an_unquoted_untrusted_string_value() {
        let fields = tokenize("type=PATH name=2F746D702F666F6F20626172 nametype=CREATE");
        assert_eq!(
            fields.get("name").map(String::as_str),
            Some("2F746D702F666F6F20626172")
        );
    }

    #[test]
    fn a_truncated_key_yields_an_empty_value_rather_than_panicking() {
        let fields = tokenize("type=SYSCALL pid=");
        assert_eq!(fields.get("pid").map(String::as_str), Some(""));
    }

    #[test]
    fn parses_the_shared_audit_event_header() {
        let fields = tokenize(SYSCALL_LINE);
        let id = parse_audit_msg_id(fields.get("msg").unwrap()).expect("must parse");
        assert_eq!(id.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(id.serial, 456);
    }

    /// Every record belonging to one audit event repeats the same
    /// `msg=audit(<secs>.<millis>:<serial>)` header — that shared id is
    /// exactly what the Filesystem sensor's assembler groups on.
    #[test]
    fn records_of_the_same_event_share_one_id() {
        let path_line =
            r#"type=PATH msg=audit(1690000000.123:456): item=1 name="/tmp/foo" nametype=DELETE"#;
        let syscall_id = parse_audit_msg_id(tokenize(SYSCALL_LINE).get("msg").unwrap()).unwrap();
        let path_id = parse_audit_msg_id(tokenize(path_line).get("msg").unwrap()).unwrap();
        assert_eq!(syscall_id, path_id);
    }

    #[test]
    fn rejects_a_malformed_header() {
        assert_eq!(parse_audit_msg_id("not-an-audit-header"), None);
        assert_eq!(parse_audit_msg_id("audit(1690000000.123)"), None);
        assert_eq!(parse_audit_msg_id("audit(nope.123:456):"), None);
    }
}
