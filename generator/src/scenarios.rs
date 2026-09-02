use osiris_sensor_api::{ProcessExecRaw, RawEventSource};

/// A minimal process/exec scenario mirroring ARCHITECTURE.md §26's worked
/// trace (sshd -> bash -> curl), narrowed to the process/exec portion per
/// Phase 1's exit criterion. Timestamps are relative nanoseconds starting
/// at `base_ts_ns`, spaced 1ms apart.
pub fn exec_chain_scenario(base_ts_ns: u64) -> Vec<ProcessExecRaw> {
    vec![
        ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 1000,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: base_ts_ns,
            start_time_mono: base_ts_ns,
            source: RawEventSource::Synthetic,
        },
        ProcessExecRaw {
            pid: 200,
            ppid: 100,
            uid: 1000,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: base_ts_ns + 1_000_000,
            start_time_mono: base_ts_ns + 1_000_000,
            source: RawEventSource::Synthetic,
        },
        ProcessExecRaw {
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: base_ts_ns + 2_000_000,
            start_time_mono: base_ts_ns + 2_000_000,
            source: RawEventSource::Synthetic,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_has_three_events_with_correct_parent_chain() {
        let events = exec_chain_scenario(1000);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].pid, 100);
        assert_eq!(events[1].ppid, events[0].pid);
        assert_eq!(events[2].ppid, events[1].pid);
    }

    #[test]
    fn scenario_events_are_time_ordered() {
        let events = exec_chain_scenario(1000);
        assert!(events[0].timestamp_ns < events[1].timestamp_ns);
        assert!(events[1].timestamp_ns < events[2].timestamp_ns);
    }
}
