//! `GET /api/v1/plugins` — runtime status of the Phase 12b WASM plugins.
//! Platform-admin only (see `auth_middleware`). The body is the plugin set's
//! `PluginStatus` rows: counters and the last failure class, never plugin
//! output, event content or file paths.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use osiris_plugin::PluginSet;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct PluginsState {
    /// `None` when no plugins are configured.
    pub plugins: Option<Arc<PluginSet>>,
}

pub fn build_plugins_router(state: PluginsState) -> Router {
    Router::new()
        .route("/api/v1/plugins", get(plugins_handler))
        .with_state(state)
}

async fn plugins_handler(State(state): State<PluginsState>) -> Json<Value> {
    let rows = state
        .plugins
        .as_ref()
        .map(|p| p.status())
        .unwrap_or_default();
    Json(json!({ "plugins": rows }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn plugins_endpoint_returns_empty_list_when_none_configured() {
        let app = build_plugins_router(PluginsState { plugins: None });
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/plugins")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v, json!({ "plugins": [] }));
    }
}
