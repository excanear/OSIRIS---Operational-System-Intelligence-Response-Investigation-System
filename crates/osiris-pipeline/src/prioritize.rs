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
                (EventType::NetworkConnect, PriorityLane::Normal),
                (EventType::NetworkAccept, PriorityLane::Normal),
                // NETWORK_CLOSE is the highest-volume network event by the
                // same reasoning FILE_WRITE got a low lane in Phase 2: every
                // connection produces at most one open event but exactly
                // one close (barring a still-open connection at shutdown),
                // and short-lived connections churn faster than sustained
                // ones open new ones — closes are the type most likely to
                // need shedding first under bus pressure.
                (EventType::NetworkClose, PriorityLane::Low),
                (EventType::DnsQuery, PriorityLane::Normal),
                (EventType::SessionLogin, PriorityLane::Normal),
                (EventType::SessionLogout, PriorityLane::Normal),
                (EventType::SessionCreate, PriorityLane::Normal),
                (EventType::SessionTerminate, PriorityLane::Normal),
                // A uid transition and a sudo invocation are the two
                // events in this phase that most directly answer "did
                // someone gain privilege" — §8.1's HIGH lane exists for
                // exactly this, and both are far rarer than the ambient
                // exec/file/network stream, so promoting them costs the
                // lower lanes nothing.
                (EventType::PrivilegeUidChange, PriorityLane::High),
                (EventType::PrivilegeSudo, PriorityLane::High),
                // A gid transition stays Normal: daemons setgid at startup
                // as a matter of routine, so it is not the rare, decisive
                // signal the two above are.
                (EventType::PrivilegeGidChange, PriorityLane::Normal),
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
        // No Phase 3+ sensor emits SOCKET_LISTEN yet (Phase 3 plan Global
        // Constraints #3) — it stays unmapped until whichever phase adds it.
        event.event_type = EventType::SocketListen;
        let table = PriorityTable::default();
        assert_eq!(prioritize(&event, &table), PriorityLane::Normal);
    }

    #[test]
    fn network_and_dns_event_types_map_to_their_configured_lanes() {
        let table = PriorityTable::default();
        for (event_type, expected) in [
            (EventType::NetworkConnect, PriorityLane::Normal),
            (EventType::NetworkAccept, PriorityLane::Normal),
            (EventType::NetworkClose, PriorityLane::Low),
            (EventType::DnsQuery, PriorityLane::Normal),
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(prioritize(&event, &table), expected, "{event_type:?}");
        }
    }

    #[test]
    fn identity_events_take_the_normal_lane() {
        let table = PriorityTable::default();
        for event_type in [
            EventType::SessionLogin,
            EventType::SessionLogout,
            EventType::SessionCreate,
            EventType::SessionTerminate,
        ] {
            let mut event = exec_event();
            event.event_type = event_type;
            assert_eq!(table.lane_for(&event), PriorityLane::Normal);
        }
    }

    /// ARCHITECTURE.md §26 step 3's own example of a HIGH-lane assignment
    /// is "an event that matters more than the ambient stream". A uid
    /// transition and a sudo invocation are exactly that; a gid transition
    /// is not — daemons setgid at startup as a matter of routine.
    #[test]
    fn uid_changes_and_sudo_take_the_high_lane_but_gid_changes_do_not() {
        let table = PriorityTable::default();

        let mut uid_change = exec_event();
        uid_change.event_type = EventType::PrivilegeUidChange;
        assert_eq!(table.lane_for(&uid_change), PriorityLane::High);

        let mut sudo = exec_event();
        sudo.event_type = EventType::PrivilegeSudo;
        assert_eq!(table.lane_for(&sudo), PriorityLane::High);

        let mut gid_change = exec_event();
        gid_change.event_type = EventType::PrivilegeGidChange;
        assert_eq!(table.lane_for(&gid_change), PriorityLane::Normal);
    }
}
