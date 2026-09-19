use osiris_sensors_identity::{parse_record, IdentityRecord};

fn fixture_lines() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ssh_sudo_session.log");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Exactly the owned records are picked out of a realistic mixed log:
/// 5 identity (2 logins, session open, session close, logout) and
/// 3 privilege (sudo, setuid, setgid). The `execve`, `setresuid`,
/// `CRED_ACQ` and `PROCTITLE` lines are ignored.
#[test]
fn parses_exactly_the_owned_records_out_of_a_realistic_mixed_audit_log() {
    let mut identity = 0;
    let mut privilege = 0;
    for line in fixture_lines() {
        match parse_record(&line) {
            Some(IdentityRecord::Identity(_)) => identity += 1,
            Some(IdentityRecord::Privilege(_)) => privilege += 1,
            None => {}
        }
    }
    assert_eq!(
        identity, 5,
        "USER_LOGIN x2, USER_START, USER_END, USER_LOGOUT"
    );
    assert_eq!(privilege, 3, "USER_CMD, setuid, setgid — NOT setresuid");
}

/// The two concurrent sessions in the fixture stay distinct, and the local
/// console login carries no remote address (Global Constraint #9's `?`
/// handling) while the SSH login does — precisely the distinction Task 6's
/// detection rule keys on.
#[test]
fn the_remote_and_local_logins_are_distinguishable_by_remote_addr_alone() {
    let logins: Vec<_> = fixture_lines()
        .iter()
        .filter_map(|l| match parse_record(l) {
            Some(IdentityRecord::Identity(i)) => Some(i),
            _ => None,
        })
        .filter(|i| i.operation == osiris_sensor_api::IdentityOperation::Login)
        .collect();
    assert_eq!(logins.len(), 2);

    let ssh = logins.iter().find(|i| i.session_id == "3").expect("ses=3");
    assert_eq!(ssh.remote_addr.as_deref(), Some("198.51.100.10"));
    assert_eq!(ssh.auth_method.as_deref(), Some("sshd"));
    assert_eq!(ssh.terminal.as_deref(), Some("/dev/pts/0"));

    let console = logins.iter().find(|i| i.session_id == "4").expect("ses=4");
    assert_eq!(
        console.remote_addr, None,
        "a tty1 login has no remote address"
    );
    assert_eq!(console.auth_method.as_deref(), Some("login"));
    assert_eq!(console.terminal.as_deref(), Some("tty1"));
}

/// The escalation the whole phase exists to see: pid 300, session 3,
/// acting uid 1000, target uid 0.
#[test]
fn the_fixtures_escalation_reports_a_real_transition_to_root() {
    let escalation = fixture_lines()
        .iter()
        .filter_map(|l| match parse_record(l) {
            Some(IdentityRecord::Privilege(p)) => Some(p),
            _ => None,
        })
        .find(|p| p.operation == osiris_sensor_api::PrivilegeOperation::UidChange)
        .expect("the setuid record must parse");
    assert_eq!(escalation.pid, 300);
    assert_eq!(escalation.ppid, 200);
    assert_eq!(escalation.uid, 1000);
    assert_eq!(escalation.target_uid, Some(0));
    assert_eq!(escalation.session_id.as_deref(), Some("3"));
}
