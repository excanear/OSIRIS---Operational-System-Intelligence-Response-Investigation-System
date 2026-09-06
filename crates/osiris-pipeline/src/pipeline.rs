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
}
