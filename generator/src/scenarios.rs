use osiris_schema::encode_device_id;
use osiris_sensor_api::{
    ContainerEventRaw, ContainerOperation, DnsEventRaw, FileEventRaw, FileOperation,
    IdentityEventRaw, IdentityOperation, NetworkDirection, NetworkEventRaw, NetworkOperation,
    PersistenceCheckpointKind, PersistenceEventRaw, PersistenceOperation, PrivilegeEventRaw,
    PrivilegeOperation, ProcessExecRaw, RawEvent, RawEventSource, SystemdEventRaw,
    SystemdOperation,
};

/// The identity the staged payload keeps across create -> write -> rename.
pub const WEB_SHELL_INODE: u64 = 200_001;
/// Major 8, minor 1 — the usual root block device, as `dev=08:01` in audit.
pub const WEB_SHELL_DEVICE_ID: u64 = encode_device_id(8, 1);
pub const WEB_SHELL_TEMP_PATH: &str = "/var/www/html/.shell.php.tmp";
pub const WEB_SHELL_FINAL_PATH: &str = "/var/www/html/shell.php";
/// The benign control file: same actor family, ordinary destination.
pub const BENIGN_NOTES_PATH: &str = "/home/user/notes.txt";
const BENIGN_NOTES_INODE: u64 = 300_777;

/// A suspicious TLD chosen to satisfy Task 6's shipped detection rule —
/// this scenario is both the DNS/Network pipeline's fixture and the rule's
/// positive fixture, the same dual role `web_shell_drop_scenario` plays for
/// Task 6/7 (now Task 6) of Phase 2.
pub const BEACON_DOMAIN: &str = "cdn-assets.xyz";
pub const BEACON_IP: &str = "203.0.113.50";

/// The audit session id the whole Phase 4a chain hangs off. A string, not
/// an integer, because §9.2's `SessionRef.session_id` is one.
pub const SSH_SESSION_ID: &str = "3";
/// The address the session was opened from — what makes Task 6's rule
/// able to say "a remote session" rather than "any escalation".
pub const SSH_REMOTE_ADDR: &str = "198.51.100.10";
/// What the escalated process writes: the canonical post-escalation
/// persistence touch, and a FILE-category event under the same session.
pub const ROOT_KEYS_PATH: &str = "/root/.ssh/authorized_keys";
const ROOT_KEYS_INODE: u64 = 400_555;
/// Where it then connects — a NETWORK-category event under the same
/// session, completing §26's identity->process->file->network chain.
pub const ESCALATION_C2_IP: &str = "203.0.113.77";

/// The backdoor systemd service Task 9's rule exists to catch.
pub const BACKDOOR_UNIT_NAME: &str = "backdoor.service";
pub const BACKDOOR_UNIT_PATH: &str = "/etc/systemd/system/backdoor.service";

/// The container id Phase 5's scenario deploys — a fixed 64-hex string
/// (a real container id's shape), reused by this scenario's own
/// detection-rule fixture and by any test asserting on the deployed
/// container's identity.
pub const DEPLOYED_CONTAINER_ID: &str = "d00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00d";
pub const DEPLOYED_CONTAINER_CGROUP_PATH: &str =
    "/system.slice/docker-d00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00d.scope";

/// A minimal process/exec scenario mirroring ARCHITECTURE.md §26's worked
/// trace (sshd -> bash -> curl). Timestamps are relative nanoseconds
/// starting at `base_ts_ns`, spaced 1ms apart.
pub fn exec_chain_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
    ]
}

/// §26's exec chain continued into the filesystem: curl stages a payload
/// under a dot-prefixed temp name, writes it, then renames it into place
/// (the atomic-drop pattern real tooling uses), followed by a benign write
/// to a home directory that must NOT trigger the web-root detection rule.
///
/// Every file event carries a real inode/device pair, and the staged file
/// keeps ONE inode across all three of its events — so this scenario
/// exercises identity-based File Story assembly, not just path matching.
pub fn web_shell_drop_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
        file_event(
            FileOperation::Create,
            WEB_SHELL_TEMP_PATH,
            None,
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 3_000_000,
        ),
        file_event(
            FileOperation::Write,
            WEB_SHELL_TEMP_PATH,
            None,
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 4_000_000,
        ),
        file_event(
            FileOperation::Rename,
            WEB_SHELL_FINAL_PATH,
            Some(WEB_SHELL_TEMP_PATH),
            WEB_SHELL_INODE,
            300,
            200,
            "/usr/bin/curl",
            "curl",
            base_ts_ns + 5_000_000,
        ),
        file_event(
            FileOperation::Write,
            BENIGN_NOTES_PATH,
            None,
            BENIGN_NOTES_INODE,
            200,
            100,
            "/bin/bash",
            "bash",
            base_ts_ns + 6_000_000,
        ),
    ]
}

/// §26's exec chain continued into DNS and the network: curl (pid 300)
/// resolves a suspicious-TLD domain, connects to the resolved address, then
/// the connection closes. Mirrors `web_shell_drop_scenario`'s shape: same
/// exec chain, a plausible actor, and identity that stays consistent across
/// events (the DNS response IP and the connection's remote address match,
/// per Phase 3 plan Global Constraints #8's `RESOLVED_TO`/`CONNECTED_TO`
/// edges) so Network Story assembly has something real to join.
pub fn network_beacon_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 1_000_000),
        exec(300, 200, "/usr/bin/curl", "curl", base_ts_ns + 2_000_000),
        RawEvent::Dns(DnsEventRaw {
            query: BEACON_DOMAIN.to_string(),
            qtype: "A".to_string(),
            response_ips: vec![BEACON_IP.to_string()],
            ttl: Some(300),
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 3_000_000,
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: BEACON_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 4_000_000,
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Close,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51000,
            remote_addr: BEACON_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 5_000_000,
            source: RawEventSource::Synthetic,
        }),
    ]
}

/// ARCHITECTURE.md §26's worked trace from its true first step: sshd
/// accepts a remote connection, audit records the login, a shell runs
/// inside that session, sudo escalates it to root, and the escalated
/// process writes root's authorized_keys and then calls out to a remote
/// address. Nine events spanning all five categories this codebase can
/// produce, every one of them under session id `SSH_SESSION_ID` once the
/// Enrich stage's `SessionResolver` has propagated it (Phase 4a plan
/// Global Constraint #5).
///
/// The logout is deliberately last: `SESSION_LOGOUT` prunes the session
/// from the resolver, so an earlier placement would leave every subsequent
/// event unattributed — which is correct behaviour, and exactly why the
/// ordering matters here.
pub fn ssh_sudo_escalation_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            // sshd authenticates as root; the user who logged in is `auid`.
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 1_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 2_000_000),
        exec(300, 200, "/usr/bin/sudo", "sudo", base_ts_ns + 3_000_000),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::Sudo,
            pid: 300,
            // USER_CMD carries no ppid — 0 is the "no parent reported"
            // convention, and the resolver still attributes this event
            // because pid 300 is already a known session member from its
            // own exec above.
            ppid: 0,
            uid: 1000,
            gid: None,
            euid: None,
            egid: None,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            // Global Constraint #9: USER_CMD does not reliably report the
            // target account, so the synthetic record does not invent one
            // either — the generator must produce records the real sensor
            // could actually have produced.
            target_uid: None,
            target_gid: None,
            command: Some("/usr/bin/tee /root/.ssh/authorized_keys".to_string()),
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 4_000_000,
            audit_serial: Some(469),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 300,
            ppid: 200,
            uid: 1000,
            gid: Some(1000),
            euid: Some(0),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 5_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Synthetic,
        }),
        file_event(
            FileOperation::Write,
            ROOT_KEYS_PATH,
            None,
            ROOT_KEYS_INODE,
            300,
            200,
            "/usr/bin/sudo",
            "sudo",
            base_ts_ns + 6_000_000,
        ),
        RawEvent::Network(NetworkEventRaw {
            operation: NetworkOperation::Connect,
            local_addr: "10.0.0.5".to_string(),
            local_port: 51001,
            remote_addr: ESCALATION_C2_IP.to_string(),
            remote_port: 443,
            proto: "tcp".to_string(),
            direction: NetworkDirection::Outbound,
            pid: Some(300),
            uid: 0,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 7_000_000,
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Logout,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 8_000_000,
            audit_serial: Some(513),
            source: RawEventSource::Synthetic,
        }),
    ]
}

/// Phase 4b's flagship trace: the same SSH-login-then-sudo-escalation
/// opening `ssh_sudo_escalation_scenario` uses, now continuing into
/// PERSISTENCE and SYSTEMD instead of FILE and NETWORK — an already-root
/// attacker installs a backdoor systemd unit file (observed by Persistence
/// Monitor's periodic scan, unattributed — no pid triggered it) and starts
/// it (observed by the audit-backed Systemd sensor, whose record's own
/// `ses=` carries the SSH session id directly). Nine events spanning five
/// categories, every one of them under session id `SSH_SESSION_ID` once
/// Task 1's fixed `SessionResolver` has propagated or directly observed it.
pub fn persistence_via_systemd_service_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 1_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 2_000_000),
        exec(300, 200, "/usr/bin/sudo", "sudo", base_ts_ns + 3_000_000),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::Sudo,
            pid: 300,
            ppid: 0,
            uid: 1000,
            gid: None,
            euid: None,
            egid: None,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            target_uid: None,
            target_gid: None,
            command: Some("/usr/bin/systemctl enable --now backdoor.service".to_string()),
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 4_000_000,
            audit_serial: Some(469),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 300,
            ppid: 200,
            uid: 1000,
            gid: Some(1000),
            euid: Some(0),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: base_ts_ns + 5_000_000,
            audit_serial: Some(470),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Persistence(PersistenceEventRaw {
            operation: PersistenceOperation::Created,
            checkpoint_kind: PersistenceCheckpointKind::SystemdUnit,
            path: BACKDOOR_UNIT_PATH.to_string(),
            content_hash: Some("b".repeat(64)),
            size: Some(96),
            timestamp_ns: base_ts_ns + 6_000_000,
            source: RawEventSource::Procfs,
        }),
        RawEvent::Systemd(SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: BACKDOOR_UNIT_NAME.to_string(),
            // Genuinely systemd's own pid on a real host (plan Global
            // Constraint #3) — never the attacker's pid 300.
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some(SSH_SESSION_ID.to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: base_ts_ns + 7_000_000,
            audit_serial: Some(512),
            source: RawEventSource::Synthetic,
        }),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Logout,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 8_000_000,
            audit_serial: Some(560),
            source: RawEventSource::Synthetic,
        }),
    ]
}

/// Phase 5's flagship scenario (plan Task 8): the same SSH-login-then-sudo
/// opening as `persistence_via_systemd_service_scenario`, continued into a
/// container deploy instead of a systemd backdoor — the natural sibling
/// vertical slice for this phase's own attacker technique (T1610, Deploy
/// Container), reached over the same remote-session precondition
/// (T1021.004) the systemd rule already established.
pub fn container_deploy_in_remote_session_scenario(base_ts_ns: u64) -> Vec<RawEvent> {
    vec![
        exec(100, 1, "/usr/sbin/sshd", "sshd", base_ts_ns),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 1_000_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }),
        exec(200, 100, "/bin/bash", "bash", base_ts_ns + 2_000_000),
        exec(300, 200, "/usr/bin/docker", "docker", base_ts_ns + 3_000_000),
        RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Create,
            container_id: DEPLOYED_CONTAINER_ID.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: DEPLOYED_CONTAINER_CGROUP_PATH.to_string(),
            // Derived from the new cgroup's `cgroup.procs` (the real
            // Linux mechanism `ContainerCgroupPoller::read_cgroup_procs_pid`
            // reads) — here, the `docker` CLI invocation itself (pid 300),
            // the one process the fallback backend can honestly observe as
            // a member of the just-created cgroup at scan time.
            pid: Some(300),
            pod_name: None,
            pod_namespace: None,
            timestamp_ns: base_ts_ns + 4_000_000,
            source: RawEventSource::Procfs,
        }),
        RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: DEPLOYED_CONTAINER_ID.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: DEPLOYED_CONTAINER_CGROUP_PATH.to_string(),
            pid: Some(300),
            pod_name: None,
            pod_namespace: None,
            timestamp_ns: base_ts_ns + 5_000_000,
            source: RawEventSource::Procfs,
        }),
        RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Logout,
            session_id: SSH_SESSION_ID.to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some(SSH_REMOTE_ADDR.to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns + 6_000_000,
            audit_serial: Some(560),
            source: RawEventSource::Synthetic,
        }),
    ]
}

fn exec(pid: u32, ppid: u32, exe_path: &str, comm: &str, timestamp_ns: u64) -> RawEvent {
    RawEvent::ProcessExec(ProcessExecRaw {
        pid,
        ppid,
        uid: 1000,
        exe_path: exe_path.to_string(),
        comm: comm.to_string(),
        timestamp_ns,
        start_time_mono: timestamp_ns,
        source: RawEventSource::Synthetic,
    })
}

#[allow(clippy::too_many_arguments)]
fn file_event(
    operation: FileOperation,
    path: &str,
    previous_path: Option<&str>,
    inode: u64,
    pid: u32,
    ppid: u32,
    exe_path: &str,
    comm: &str,
    timestamp_ns: u64,
) -> RawEvent {
    RawEvent::File(FileEventRaw {
        operation,
        path: path.to_string(),
        previous_path: previous_path.map(|p| p.to_string()),
        inode: Some(inode),
        device_id: Some(WEB_SHELL_DEVICE_ID),
        mode: Some(0o100644),
        owner_uid: Some(33),
        owner_gid: Some(33),
        pid,
        ppid,
        uid: 1000,
        exe_path: exe_path.to_string(),
        comm: comm.to_string(),
        timestamp_ns,
        audit_serial: None,
        source: RawEventSource::Synthetic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::FileOperation;

    fn exec_events(scenario: &[RawEvent]) -> Vec<&ProcessExecRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::ProcessExec(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    fn file_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::FileEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::File(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn exec_chain_scenario_has_three_execs_with_the_correct_parent_chain() {
        let scenario = exec_chain_scenario(1000);
        let execs = exec_events(&scenario);
        assert_eq!(scenario.len(), 3);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[0].pid, 100);
        assert_eq!(execs[1].ppid, execs[0].pid);
        assert_eq!(execs[2].ppid, execs[1].pid);
    }

    #[test]
    fn every_scenario_is_strictly_time_ordered() {
        for scenario in [
            exec_chain_scenario(1000),
            web_shell_drop_scenario(1000),
            ssh_sudo_escalation_scenario(1000),
            persistence_via_systemd_service_scenario(1000),
        ] {
            for pair in scenario.windows(2) {
                assert!(
                    pair[0].timestamp_ns() < pair[1].timestamp_ns(),
                    "scenario events must be strictly increasing in time"
                );
            }
        }
    }

    /// The scenario mirrors ARCHITECTURE.md §26's sshd -> bash -> curl trace
    /// and extends it into the filesystem: curl stages a payload under a
    /// temp name, writes it, then renames it into place — the classic
    /// atomic web-shell drop, and the exact shape Task 7's detection rule
    /// is written against.
    #[test]
    fn web_shell_drop_scenario_has_the_full_exec_then_file_chain() {
        let scenario = web_shell_drop_scenario(1000);
        assert_eq!(scenario.len(), 7);

        let execs = exec_events(&scenario);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[2].exe_path, "/usr/bin/curl");
        assert_eq!(execs[2].pid, 300);

        let files = file_events(&scenario);
        assert_eq!(files.len(), 4);

        assert_eq!(files[0].operation, FileOperation::Create);
        assert_eq!(files[0].path, WEB_SHELL_TEMP_PATH);
        assert_eq!(files[0].pid, 300);

        assert_eq!(files[1].operation, FileOperation::Write);
        assert_eq!(files[1].path, WEB_SHELL_TEMP_PATH);

        assert_eq!(files[2].operation, FileOperation::Rename);
        assert_eq!(files[2].path, WEB_SHELL_FINAL_PATH);
        assert_eq!(files[2].previous_path.as_deref(), Some(WEB_SHELL_TEMP_PATH));

        // The benign control: a shell writing to a user's home directory
        // must NOT match the web-root rule, which is what makes the
        // detection test in Task 7 meaningful rather than vacuous.
        assert_eq!(files[3].operation, FileOperation::Write);
        assert_eq!(files[3].path, BENIGN_NOTES_PATH);
        assert_eq!(files[3].pid, 200);
    }

    /// The staged file keeps one inode across create, write and rename —
    /// this is precisely what lets Task 8's File Story follow the file from
    /// its temp name to its final name.
    #[test]
    fn the_staged_file_keeps_one_identity_across_create_write_and_rename() {
        let scenario = web_shell_drop_scenario(1000);
        let files = file_events(&scenario);
        for file in files.iter().take(3) {
            assert_eq!(file.inode, Some(WEB_SHELL_INODE));
            assert_eq!(file.device_id, Some(WEB_SHELL_DEVICE_ID));
        }
        assert_ne!(files[3].inode, Some(WEB_SHELL_INODE));
    }

    fn network_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::NetworkEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Network(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    fn dns_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::DnsEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Dns(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn network_beacon_scenario_has_the_full_exec_then_dns_then_network_chain() {
        let scenario = network_beacon_scenario(1000);
        assert_eq!(scenario.len(), 6);

        let execs = exec_events(&scenario);
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[2].exe_path, "/usr/bin/curl");
        assert_eq!(execs[2].pid, 300);

        let dns = dns_raw_events(&scenario);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].query, BEACON_DOMAIN);
        assert_eq!(dns[0].response_ips, vec![BEACON_IP.to_string()]);
        assert_eq!(dns[0].pid, Some(300));

        let net = network_raw_events(&scenario);
        assert_eq!(net.len(), 2);
        assert_eq!(net[0].operation, osiris_sensor_api::NetworkOperation::Connect);
        assert_eq!(net[0].remote_addr, BEACON_IP);
        assert_eq!(net[0].pid, Some(300));
        assert_eq!(net[1].operation, osiris_sensor_api::NetworkOperation::Close);
        assert_eq!(net[1].remote_addr, BEACON_IP);
    }

    #[test]
    fn network_beacon_scenario_is_strictly_time_ordered() {
        let scenario = network_beacon_scenario(1000);
        for pair in scenario.windows(2) {
            assert!(pair[0].timestamp_ns() < pair[1].timestamp_ns());
        }
    }

    /// The DNS query resolves to the same IP the connect/close events cite
    /// — this is precisely what lets Task 7's Network Story follow the
    /// domain to its connections via `RESOLVED_TO`.
    #[test]
    fn the_beacons_resolved_ip_matches_its_connections_remote_address() {
        let scenario = network_beacon_scenario(1000);
        let dns = dns_raw_events(&scenario);
        let net = network_raw_events(&scenario);
        assert_eq!(dns[0].response_ips[0], net[0].remote_addr);
    }

    fn identity_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::IdentityEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Identity(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    fn privilege_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::PrivilegeEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Privilege(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// ARCHITECTURE.md §26's worked trace, now from its actual first step:
    /// sshd accepts a connection, PAM/audit records the session, a shell
    /// runs inside it, sudo escalates to root, and the escalated process
    /// then touches the filesystem and the network — so the resulting
    /// stored chain spans IDENTITY, PROCESS, PRIVILEGE, FILE and NETWORK,
    /// all under one session id.
    #[test]
    fn ssh_sudo_escalation_scenario_spans_all_five_categories_under_one_session() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        assert_eq!(scenario.len(), 9);

        let identity = identity_raw_events(&scenario);
        assert_eq!(identity.len(), 2, "one login, one logout");
        assert_eq!(identity[0].operation, osiris_sensor_api::IdentityOperation::Login);
        assert_eq!(identity[0].session_id, SSH_SESSION_ID);
        assert_eq!(identity[0].remote_addr.as_deref(), Some(SSH_REMOTE_ADDR));
        assert_eq!(identity[0].auth_method.as_deref(), Some("sshd"));
        assert_eq!(identity[0].pid, 100, "the login is rooted at sshd's pid");
        assert_eq!(
            identity[1].operation,
            osiris_sensor_api::IdentityOperation::Logout
        );

        assert_eq!(exec_events(&scenario).len(), 3, "sshd, bash, sudo");

        let privilege = privilege_raw_events(&scenario);
        assert_eq!(privilege.len(), 2, "one sudo invocation, one uid change");
        assert_eq!(privilege[0].operation, osiris_sensor_api::PrivilegeOperation::Sudo);
        assert_eq!(privilege[1].operation, osiris_sensor_api::PrivilegeOperation::UidChange);
        assert_eq!(privilege[1].uid, 1000);
        assert_eq!(privilege[1].target_uid, Some(0), "escalation to root");

        assert_eq!(file_events(&scenario).len(), 1);
        assert_eq!(file_events(&scenario)[0].path, ROOT_KEYS_PATH);
        assert_eq!(network_raw_events(&scenario).len(), 1);
        assert_eq!(network_raw_events(&scenario)[0].remote_addr, ESCALATION_C2_IP);
    }

    /// The escalating process must be a descendant of the login's pid, or
    /// the Enrich stage's ppid-inheritance chain cannot reach it and the
    /// whole phase's correlation silently produces nothing.
    #[test]
    fn every_post_login_actor_descends_from_the_logins_pid() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        let execs = exec_events(&scenario);
        assert_eq!((execs[0].pid, execs[0].ppid), (100, 1), "sshd");
        assert_eq!((execs[1].pid, execs[1].ppid), (200, 100), "bash under sshd");
        assert_eq!((execs[2].pid, execs[2].ppid), (300, 200), "sudo under bash");

        let escalation = privilege_raw_events(&scenario)[1];
        assert_eq!((escalation.pid, escalation.ppid), (300, 200));
        // The file and network events name pid 300, which by then is a
        // known session member via its own exec.
        assert_eq!(file_events(&scenario)[0].pid, 300);
        assert_eq!(network_raw_events(&scenario)[0].pid, Some(300));
    }

    /// The logout is last, so it cannot prune the session before the events
    /// that must inherit it are processed.
    #[test]
    fn ssh_sudo_escalation_scenario_is_strictly_time_ordered_and_ends_with_the_logout() {
        let scenario = ssh_sudo_escalation_scenario(1_000_000_000);
        let timestamps: Vec<u64> = scenario.iter().map(RawEvent::timestamp_ns).collect();
        let mut sorted = timestamps.clone();
        sorted.sort();
        assert_eq!(timestamps, sorted);
        assert!(timestamps.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(scenario.last(), Some(RawEvent::Identity(i)) if i.operation
            == osiris_sensor_api::IdentityOperation::Logout));
    }

    fn systemd_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::SystemdEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Systemd(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    fn persistence_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::PersistenceEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Persistence(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// The Phase 4b flagship trace: an already-escalated attacker (this
    /// scenario opens with the same SSH-login-then-sudo shape
    /// `ssh_sudo_escalation_scenario` established) installs a backdoor
    /// systemd service and starts it — the identity->process->privilege
    /// chain now continuing into PERSISTENCE and SYSTEMD, the two
    /// categories this phase adds. Nine events across five categories,
    /// under one session id once the Enrich stage's `SessionResolver` (and
    /// Task 1's fix) has propagated it.
    #[test]
    fn persistence_via_systemd_service_scenario_spans_all_five_categories_under_one_session() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        assert_eq!(scenario.len(), 9);

        assert_eq!(exec_events(&scenario).len(), 3, "sshd, bash, sudo");

        let identity = identity_raw_events(&scenario);
        assert_eq!(identity.len(), 2, "one login, one logout");
        assert_eq!(identity[0].session_id, SSH_SESSION_ID);

        let privilege = privilege_raw_events(&scenario);
        assert_eq!(privilege.len(), 2, "one sudo invocation, one uid change");
        assert_eq!(privilege[1].target_uid, Some(0), "escalation to root");

        let persistence = persistence_raw_events(&scenario);
        assert_eq!(persistence.len(), 1);
        assert_eq!(persistence[0].path, BACKDOOR_UNIT_PATH);
        assert_eq!(
            persistence[0].checkpoint_kind,
            osiris_sensor_api::PersistenceCheckpointKind::SystemdUnit
        );

        let systemd = systemd_raw_events(&scenario);
        assert_eq!(systemd.len(), 1);
        assert_eq!(systemd[0].unit_name, BACKDOOR_UNIT_NAME);
        assert_eq!(
            systemd[0].operation,
            osiris_sensor_api::SystemdOperation::Start
        );
        assert_eq!(
            systemd[0].session_id.as_deref(),
            Some(SSH_SESSION_ID),
            "the service-start record's own observed session is what makes \
             Task 9's rule expressible"
        );
        // Genuinely systemd's own pid, not the attacker's shell — plan
        // Global Constraint #3's disclosure, pinned as a test so a future
        // edit cannot casually "fix" it into pid 300 by mistake.
        assert_eq!(systemd[0].pid, 1);
    }

    /// The exec chain must form a real ancestry (Global Constraint #2 in
    /// Phase 4a's sense: the generator must produce records the real
    /// sensors could actually have produced) even though the Persistence
    /// and Systemd events themselves carry no pid the chain reaches.
    #[test]
    fn every_exec_event_descends_from_the_logins_pid() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        let execs = exec_events(&scenario);
        assert_eq!((execs[0].pid, execs[0].ppid), (100, 1), "sshd");
        assert_eq!((execs[1].pid, execs[1].ppid), (200, 100), "bash under sshd");
        assert_eq!((execs[2].pid, execs[2].ppid), (300, 200), "sudo under bash");
    }

    #[test]
    fn persistence_via_systemd_service_scenario_is_strictly_time_ordered_and_ends_with_the_logout() {
        let scenario = persistence_via_systemd_service_scenario(1_000_000_000);
        let timestamps: Vec<u64> = scenario.iter().map(RawEvent::timestamp_ns).collect();
        let mut sorted = timestamps.clone();
        sorted.sort();
        assert_eq!(timestamps, sorted);
        assert!(timestamps.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(scenario.last(), Some(RawEvent::Identity(i)) if i.operation
            == osiris_sensor_api::IdentityOperation::Logout));
    }

    fn container_raw_events(scenario: &[RawEvent]) -> Vec<&osiris_sensor_api::ContainerEventRaw> {
        scenario
            .iter()
            .filter_map(|e| match e {
                RawEvent::Container(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn container_deploy_in_remote_session_scenario_spans_process_identity_and_container_categories() {
        let scenario = container_deploy_in_remote_session_scenario(1_000_000_000);
        assert_eq!(scenario.len(), 7);

        assert_eq!(exec_events(&scenario).len(), 3, "sshd, bash, docker");

        let identity = identity_raw_events(&scenario);
        assert_eq!(identity.len(), 2, "one login, one logout");
        assert_eq!(identity[0].session_id, SSH_SESSION_ID);
        assert_eq!(identity[0].remote_addr.as_deref(), Some(SSH_REMOTE_ADDR));

        let containers = container_raw_events(&scenario);
        assert_eq!(containers.len(), 2, "one create, one start");
        assert_eq!(containers[0].operation, ContainerOperation::Create);
        assert_eq!(containers[1].operation, ContainerOperation::Start);
        for c in &containers {
            assert_eq!(c.container_id, DEPLOYED_CONTAINER_ID);
            assert_eq!(c.runtime, "cgroup");
            assert!(c.cgroup_path.contains(DEPLOYED_CONTAINER_ID));
            assert_eq!(
                c.pid,
                Some(300),
                "the docker CLI's own pid — the fallback backend's honest \
                 cgroup.procs-derived actor"
            );
        }
    }

    /// Pid 300 (the `docker` CLI invocation) is a known session member via
    /// its own exec, exactly like `ssh_sudo_escalation_scenario`'s own
    /// `every_post_login_actor_descends_from_the_logins_pid` proves for
    /// its escalation step — this is what makes Task 9's rule expressible.
    #[test]
    fn the_container_events_actor_descends_from_the_logins_pid() {
        let scenario = container_deploy_in_remote_session_scenario(1_000_000_000);
        let execs = exec_events(&scenario);
        assert_eq!((execs[2].pid, execs[2].ppid), (300, 200), "docker under bash");
        let containers = container_raw_events(&scenario);
        assert_eq!(containers[1].pid, Some(300));
    }

    #[test]
    fn container_deploy_in_remote_session_scenario_is_strictly_time_ordered_and_ends_with_the_logout() {
        let scenario = container_deploy_in_remote_session_scenario(1_000_000_000);
        let timestamps: Vec<u64> = scenario.iter().map(RawEvent::timestamp_ns).collect();
        let mut sorted = timestamps.clone();
        sorted.sort();
        assert_eq!(timestamps, sorted);
        assert!(timestamps.windows(2).all(|w| w[0] < w[1]));
        assert!(matches!(scenario.last(), Some(RawEvent::Identity(i)) if i.operation
            == osiris_sensor_api::IdentityOperation::Logout));
    }
}
