use osiris_schema::{CanonicalEvent, EventType};
use serde::{Deserialize, Serialize};

/// The Event Bus's five priority lanes (ARCHITECTURE.md §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PriorityLane {
    Critical,
    High,
    Normal,
    Low,
    Verbose,
}

/// A configurable event_type -> lane table (ARCHITECTURE.md §7.1 step 5).
///
/// Backed by a linear-scan `Vec<(EventType, PriorityLane)>` rather than a
/// `HashMap`: `EventType` (osiris-schema, Phase 0, frozen) does not derive
/// `Hash`, and this table holds five entries as of Phase 2, so a small
/// `Vec` scan is still both sufficient and simpler than a map.
pub struct PriorityTable {
    table: Vec<(EventType, PriorityLane)>,
    default_lane: PriorityLane,
}

impl Default for PriorityTable {
    fn default() -> Self {
        Self {
            table: vec![
                (EventType::ProcessExec, PriorityLane::Normal),
                (EventType::FileCreate, PriorityLane::Normal),
                (EventType::FileDelete, PriorityLane::Normal),
                (EventType::FileRename, PriorityLane::Normal),
                // See the lane rationale in the tests: FILE_WRITE is the one
                // high-volume type this phase emits.
                (EventType::FileWrite, PriorityLane::Low),
            ],
            default_lane: PriorityLane::Normal,
        }
    }
}

impl PriorityTable {
    pub fn lane_for(&self, event: &CanonicalEvent) -> PriorityLane {
        self.table
            .iter()
            .find(|(event_type, _)| *event_type == event.event_type)
            .map(|(_, lane)| *lane)
            .unwrap_or(self.default_lane)
    }
}

/// Prioritize stage (ARCHITECTURE.md §7.1 step 5): assigns a lane.
pub fn prioritize(event: &CanonicalEvent, table: &PriorityTable) -> PriorityLane {
    table.lane_for(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn exec_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn process_exec_defaults_to_normal_lane() {
        let table = PriorityTable::default();
        assert_eq!(prioritize(&exec_event(), &table), PriorityLane::Normal);
    }

    #[test]
    fn file_event_types_map_to_their_configured_lanes() {
        let table = PriorityTable::default();
        for (event_type, expected) in [
            (EventType::FileCreate, PriorityLane::Normal),
            (EventType::FileDelete, PriorityLane::Normal),
            (EventType::FileRename, PriorityLane::Normal),
            // FILE_WRITE is the highest-volume file event by a wide margin
            // (every write to a watched path), so it gets a lane that can be
            // shed first under pressure — §8.1's whole reason for lanes.
            (EventType::FileWrite, PriorityLane::Low),
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(prioritize(&event, &table), expected, "{event_type:?}");
        }
    }

    #[test]
    fn unmapped_event_type_falls_back_to_default_lane() {
        let mut event = exec_event();
        // NETWORK_CONNECT arrives in Phase 3; until then it is unmapped.
        event.event_type = EventType::NetworkConnect;
        let table = PriorityTable::default();
        assert_eq!(prioritize(&event, &table), PriorityLane::Normal);
    }
}
