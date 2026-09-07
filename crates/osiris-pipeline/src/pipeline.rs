use osiris_schema::{CanonicalEvent, HostRef};
use osiris_sensor_api::RawEvent;

use crate::enrich::enrich;
use crate::normalize::normalize;
use crate::prioritize::{prioritize, PriorityLane, PriorityTable};
use crate::process_resolver::ProcessResolver;
use crate::validate::validate;

/// A CanonicalEvent tagged with the lane it was assigned (what Task 3's
/// Event Bus keys its five channels on).
#[derive(Debug, Clone)]
pub struct PrioritizedEvent {
    pub event: CanonicalEvent,
    pub lane: PriorityLane,
}

/// The single fan-in pipeline (ARCHITECTURE.md §3.2's "why one shared
/// pipeline instance, not one per sensor"): Collect happens in the sensor
/// (Task 1/5/6); everything from Normalize onward happens here, in this
/// fixed order, for every event regardless of originating sensor.
pub struct Pipeline {
    host: HostRef,
    boot_id: String,
    resolver: ProcessResolver,
    priority_table: PriorityTable,
}

impl Pipeline {
    pub fn new(host: HostRef, boot_id: String) -> Self {
        Self {
            host,
            boot_id,
            resolver: ProcessResolver::new(),
            priority_table: PriorityTable::default(),
        }
    }

    /// Runs Normalize -> Enrich(local) -> Validate -> Prioritize on one raw
    /// event (ARCHITECTURE.md §7.1). Validation failures are tagged, never
    /// dropped — the caller always gets a PrioritizedEvent back.
    pub fn process(&mut self, raw: RawEvent) -> PrioritizedEvent {
        let event = normalize(raw, &self.host, &self.boot_id);
        let mut event = enrich(event, &self.boot_id, &mut self.resolver);
        validate(&mut event);
        let lane = prioritize(&event, &self.priority_table);
        PrioritizedEvent { event, lane }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_sensor_api::{ProcessExecRaw, RawEventSource};
    use uuid::Uuid;

    fn test_host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    #[test]
    fn end_to_end_pipeline_produces_valid_normal_lane_event() {
        let mut pipeline = Pipeline::new(test_host(), "boot-1".to_string());
        let raw = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            start_time_mono: 1,
            source: RawEventSource::Synthetic,
        });
        let result = pipeline.process(raw);
        assert_eq!(result.lane, PriorityLane::Normal);
        assert!(!result.event.tags.contains(&"INVALID".to_string()));
        assert_eq!(result.event.boot_id, "boot-1");
    }

    #[test]
    fn second_event_resolves_parent_from_first() {
        let mut pipeline = Pipeline::new(test_host(), "boot-1".to_string());
        let bash = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 1,
            start_time_mono: 1,
            source: RawEventSource::Synthetic,
        }));
        let curl = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 200,
            ppid: 100,
            uid: 0,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 2,
            start_time_mono: 2,
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(
            curl.event.parent_process.unwrap().process_key,
            bash.event.process.unwrap().process_key
        );
    }

    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for a
    /// file event that follows its own process's exec — the shape every
    /// real trace has.
    #[test]
    fn file_event_following_its_process_exec_is_fully_resolved_and_valid() {
        use osiris_sensor_api::{FileEventRaw, FileOperation};
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let curl = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));

        let write = pipeline.process(RawEvent::File(FileEventRaw {
            operation: FileOperation::Write,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));

        assert_eq!(write.lane, PriorityLane::Low);
        assert!(!write.event.tags.contains(&"INVALID".to_string()));
        assert!(!write
            .event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
        assert_eq!(
            write.event.process.as_ref().unwrap().process_key,
            curl.event.process.as_ref().unwrap().process_key,
            "the file event must be attributed to the same process entity as its exec"
        );
        assert_eq!(write.event.relationships.len(), 1);
        assert_eq!(
            write.event.file.as_ref().unwrap().path,
            "/var/www/html/shell.php"
        );
    }
}
