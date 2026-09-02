use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use osiris_sensor_api::SensorHealth;
use serde::Serialize;

use crate::agent::Agent;
use crate::lifecycle::AgentLifecycle;

#[derive(Debug, Serialize)]
pub struct AgentStatus {
    pub lifecycle: AgentLifecycle,
    pub sensors: Vec<SensorHealth>,
}

/// The Phase 1 substitute for the UDS local control endpoint (plan Global
/// Constraints #4): a tiny axum router bound to a loopback address, one
/// route (`GET /status`), used by the CLI's `osiris status` (Task 9).
pub async fn serve_status(agent: Arc<Agent>, addr: SocketAddr) -> std::io::Result<()> {
    let app = Router::new().route("/status", get(status_handler)).with_state(agent);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn status_handler(State(agent): State<Arc<Agent>>) -> Json<AgentStatus> {
    Json(agent.status_snapshot().await)
}
