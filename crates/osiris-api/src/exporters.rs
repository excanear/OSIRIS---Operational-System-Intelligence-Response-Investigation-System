//! `GET /api/v1/exporters` — runtime status of the Phase 12a exporters.
//! Platform-admin only (see `auth_middleware`). The body is the hub's
//! `ExporterStatus` rows, which carry counters and the last error text but
//! never configuration, credentials or URLs.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use osiris_export::ExportHub;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct ExportersState {
    /// `None` when no exporters are configured.
    pub hub: Option<Arc<ExportHub>>,
}

pub fn build_exporters_router(state: ExportersState) -> Router {
    Router::new()
        .route("/api/v1/exporters", get(exporters_handler))
        .with_state(state)
}

async fn exporters_handler(State(state): State<ExportersState>) -> Json<Value> {
    let rows = state.hub.as_ref().map(|h| h.status()).unwrap_or_default();
    Json(json!({ "exporters": rows }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    async fn get_body(app: Router) -> (StatusCode, String) {
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/exporters")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn exporters_endpoint_returns_empty_list_when_none_configured() {
        let app = build_exporters_router(ExportersState { hub: None });
        let (status, body) = get_body(app).await;
        assert_eq!(status, StatusCode::OK);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, json!({ "exporters": [] }));
    }

    #[tokio::test]
    async fn exporters_endpoint_never_returns_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let headers = dir.path().join("headers");
        let key = dir.path().join("key");
        std::fs::write(&headers, "Authorization: Bearer SECRET\n").unwrap();
        std::fs::write(&key, "SECRET-HMAC\n").unwrap();
        let yaml = format!(
            "- {{name: hook, kind: webhook, url: 'http://127.0.0.1:9/x?token=SECRET', \
             headers_file: '{}', hmac_key_file: '{}', max_retries: 0, flush_interval_ms: 10}}",
            headers
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/"),
            key.to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/"),
        );
        let cfgs: Vec<osiris_export::ExporterConfig> = serde_yaml::from_str(&yaml).unwrap();
        let built = osiris_export::build_exporters(&cfgs, "test").unwrap();
        let hub = ExportHub::start(built, None, CancellationToken::new());
        // Port 9 refuses: the worker records a (transient) last_error.
        let event = {
            let mut e: osiris_schema::CanonicalEvent = serde_json::from_value(json!({
                "event_id": uuid::Uuid::now_v7(),
                "schema_version": osiris_schema::SCHEMA_VERSION,
                "host_id": uuid::Uuid::new_v4(),
                "boot_id": "b", "timestamp": 1, "monotonic_timestamp": 1,
                "event_type": "PROCESS_EXEC", "category": "PROCESS", "severity": "INFO",
                "host": {"host_id": uuid::Uuid::new_v4(), "hostname": "h", "distro": "d",
                         "kernel_version": "k", "cloud": null},
                "source": "SYNTHETIC", "provider": "t", "relationships": [], "tags": [],
                "event_data": {}
            }))
            .unwrap();
            e.tags.push("x".into());
            e
        };
        hub.offer(&[event], &[]);
        for _ in 0..50 {
            if hub.status()[0].last_error.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(hub.status()[0].last_error.is_some(), "no error recorded");

        let app = build_exporters_router(ExportersState {
            hub: Some(hub.clone()),
        });
        let (status, body) = get_body(app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("SECRET"), "secret leaked: {body}");
        assert!(!body.contains("token="), "query string leaked: {body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["exporters"][0]["name"], "hook");
        assert_eq!(v["exporters"][0]["kind"], "webhook");
        hub.shutdown().await;
    }
}
