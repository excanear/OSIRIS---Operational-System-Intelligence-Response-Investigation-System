use axum::Router;
use tower_http::cors::CorsLayer;

/// Wraps `app` in a permissive CORS layer only when `dev_cors` is
/// explicitly `Some(true)` (`ServerConfig::dev_cors`) — a missing or
/// `false` value leaves `app` untouched, so a production config that
/// never mentions `dev_cors` stays closed by default.
pub fn apply_dev_cors(app: Router, dev_cors: Option<bool>) -> Router {
    if dev_cors == Some(true) {
        app.layer(CorsLayer::permissive())
    } else {
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    #[tokio::test]
    async fn dev_cors_none_adds_no_allow_origin_header() {
        let app = apply_dev_cors(test_router(), None);
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn dev_cors_false_adds_no_allow_origin_header() {
        let app = apply_dev_cors(test_router(), Some(false));
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn dev_cors_true_sets_allow_origin_header() {
        let app = apply_dev_cors(test_router(), Some(true));
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_some());
    }
}
