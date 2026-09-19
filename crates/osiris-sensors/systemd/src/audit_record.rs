use osiris_fileutil::{parse_id, split_record, usable_session};
use osiris_sensor_api::{RawEventSource, SystemdEventRaw, SystemdOperation};

/// Parses one auditd line into a `SystemdEventRaw`, or `None` when the line
/// is not a `SERVICE_START`/`SERVICE_STOP` record, or is one but is missing
/// a field this parser requires (`unit=`, `pid=`, `uid=`) — never a panic,
/// never a half-built event.
pub fn parse_record(line: &str) -> Option<SystemdEventRaw> {
    let parts = split_record(line)?;
    let operation = match parts.record_type.as_str() {
        "SERVICE_START" => SystemdOperation::Start,
        "SERVICE_STOP" => SystemdOperation::Stop,
        _ => return None,
    };
    let unit_name = parts.get("unit")?.to_string();
    let exe_path = parts.get("exe").unwrap_or_default().to_string();
    Some(SystemdEventRaw {
        operation,
        unit_name,
        pid: parts.get("pid")?.parse().ok()?,
        uid: parts.get("uid")?.parse().ok()?,
        auid: parse_id(parts.get("auid")),
        session_id: usable_session(parts.get("ses")),
        success: parts.get("res") == Some("success"),
        comm: parts.get("comm").unwrap_or_default().to_string(),
        exe_path,
        timestamp_ns: parts.id.timestamp_ns,
        audit_serial: Some(parts.id.serial),
        source: RawEventSource::Audit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_START: &str = r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 auid=1000 ses=3 subj=unconfined msg='unit=backdoor.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;
    const SERVICE_STOP: &str = r#"type=SERVICE_STOP msg=audit(1690000010.456:512): pid=1 uid=0 auid=1000 ses=3 subj=unconfined msg='unit=backdoor.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;
    const SERVICE_START_NO_SESSION: &str = r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=sshd.service comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'"#;

    #[test]
    fn parses_a_service_start_record() {
        let raw = parse_record(SERVICE_START).expect("must parse");
        assert_eq!(raw.operation, SystemdOperation::Start);
        assert_eq!(raw.unit_name, "backdoor.service");
        assert_eq!(raw.pid, 1);
        assert_eq!(raw.uid, 0);
        assert_eq!(raw.auid, Some(1000));
        assert_eq!(raw.session_id.as_deref(), Some("3"));
        assert!(raw.success);
        assert_eq!(raw.comm, "systemd");
        assert_eq!(raw.exe_path, "/usr/lib/systemd/systemd");
        assert_eq!(raw.timestamp_ns, 1_690_000_000_123_000_000);
        assert_eq!(raw.audit_serial, Some(501));
    }

    #[test]
    fn parses_a_service_stop_record() {
        let raw = parse_record(SERVICE_STOP).expect("must parse");
        assert_eq!(raw.operation, SystemdOperation::Stop);
        assert_eq!(raw.unit_name, "backdoor.service");
    }

    /// Unlike Identity's `USER_LOGIN`, a session-less SERVICE_START is NOT
    /// dropped — a unit started at boot, before any login, genuinely has no
    /// session to report, and that is still a real, storable Systemd event
    /// (unlike a failed login, nothing here depends on a session existing
    /// to be meaningful).
    #[test]
    fn a_session_less_service_start_is_still_parsed_with_session_id_none() {
        let raw = parse_record(SERVICE_START_NO_SESSION).expect("must parse");
        assert!(raw.session_id.is_none());
        assert!(raw.auid.is_none());
    }

    #[test]
    fn ignores_records_of_other_types() {
        assert!(
            parse_record(r#"type=SERVICE_RELOAD msg=audit(1690000000.123:501): pid=1 uid=0"#)
                .is_none()
        );
        assert!(parse_record("not an audit record at all").is_none());
    }

    #[test]
    fn returns_none_when_the_required_unit_field_is_missing() {
        assert!(parse_record(
            r#"type=SERVICE_START msg=audit(1690000000.123:501): pid=1 uid=0 msg='comm="systemd" res=success'"#
        )
        .is_none());
    }
}
