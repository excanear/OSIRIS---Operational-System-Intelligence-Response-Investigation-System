use osiris_schema::encode_device_id;
use osiris_sensor_api::{FileEventRaw, FileOperation, ProcessExecRaw, RawEvent, RawEventSource};

/// The identity the staged payload keeps across create -> write -> rename.
pub const WEB_SHELL_INODE: u64 = 200_001;
/// Major 8, minor 1 — the usual root block device, as `dev=08:01` in audit.
pub const WEB_SHELL_DEVICE_ID: u64 = encode_device_id(8, 1);
pub const WEB_SHELL_TEMP_PATH: &str = "/var/www/html/.shell.php.tmp";
pub const WEB_SHELL_FINAL_PATH: &str = "/var/www/html/shell.php";
/// The benign control file: same actor family, ordinary destination.
pub const BENIGN_NOTES_PATH: &str = "/home/user/notes.txt";
const BENIGN_NOTES_INODE: u64 = 300_777;

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
        for scenario in [exec_chain_scenario(1000), web_shell_drop_scenario(1000)] {
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
}
