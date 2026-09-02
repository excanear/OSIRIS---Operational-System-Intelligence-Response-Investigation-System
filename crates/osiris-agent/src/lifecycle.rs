use serde::{Deserialize, Serialize};

/// ARCHITECTURE.md §3.1 point 3. Phase 1 code only ever reaches
/// Running/Stopped; Degraded/Draining are defined now (for the API's
/// benefit) but unreachable this phase — there is no disruptive-config-
/// triggered Degraded transition without hot-reload (plan Global
/// Constraints #6), and Draining's flush semantics need the DiskSpool this
/// phase also defers (Global Constraints #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentLifecycle { Initializing, Running, Degraded, Draining, Stopped }
