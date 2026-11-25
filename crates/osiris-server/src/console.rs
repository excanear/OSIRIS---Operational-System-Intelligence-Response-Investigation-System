//! Serves the built Console (`console_dir`) on every path no API route claims.
//!
//! Mounted as the router's fallback *after* the auth gate layer, so the
//! static files are public while every registered API route stays gated.
//! Nothing under `/api/` is ever answered with Console content.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

pub const CONSOLE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
const CACHE_INDEX: &str = "no-cache";
const CACHE_ASSET: &str = "public, max-age=31536000, immutable";

struct Console {
    /// Canonical `console_dir`; every served file must resolve inside it.
    root: PathBuf,
    serve: ServeDir<ServeFile>,
}

/// Serves `console_dir` as the fallback of `app`. Returns `app` unchanged
/// when `console_dir` is `None`, or (with a warning) when it is missing or
/// has no `index.html`. HSTS is not set here: when `tls` is on, the
/// `api_tls` server's `with_hsts` already adds it to every response.
pub fn attach_console(app: Router, console_dir: Option<&Path>, tls: bool) -> Router {
    let Some(dir) = console_dir else {
        return app;
    };
    let root = match std::fs::canonicalize(dir) {
        Ok(root) if root.join("index.html").is_file() => root,
        _ => {
            tracing::warn!(
                console_dir = %dir.display(),
                "console_dir is missing or has no index.html; serving the API only"
            );
            return app;
        }
    };
    tracing::info!(console_dir = %root.display(), tls, "serving the Console");
    let serve = ServeDir::new(&root).fallback(ServeFile::new(root.join("index.html")));
    let console = Arc::new(Console { root, serve });
    app.fallback_service(axum::routing::any(serve_console).with_state(console))
}

async fn serve_console(State(console): State<Arc<Console>>, req: Request) -> Response {
    let path = req.uri().path().to_owned();
    if path == "/api" || path.starts_with("/api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut resp = if !matches!(*req.method(), Method::GET | Method::HEAD) {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
        )
            .into_response()
    } else {
        match resolve(&console.root, &path) {
            Resolved::Refused => StatusCode::NOT_FOUND.into_response(),
            resolved => {
                let immutable = path.starts_with("/assets/") && resolved == Resolved::File;
                let mut served = match console.serve.clone().oneshot(req).await {
                    Ok(r) => r.map(Body::new),
                    Err(never) => match never {},
                };
                let cache = if immutable && served.status() == StatusCode::OK {
                    CACHE_ASSET
                } else {
                    CACHE_INDEX
                };
                served
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
                served
            }
        }
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONSOLE_CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

#[derive(Debug, PartialEq)]
enum Resolved {
    /// An existing file inside the root.
    File,
    /// Nothing there: `ServeDir` falls back to `index.html`.
    Missing,
    /// Traversal, an absolute/prefixed component, or a symlink leaving the root.
    Refused,
}

/// Mirrors `ServeDir`'s own path decoding and component checks, then
/// canonicalizes what exists so a symlink cannot lead outside `root`
/// (`ServeDir` follows symlinks without checking).
fn resolve(root: &Path, request_path: &str) -> Resolved {
    let trimmed = request_path.trim_start_matches('/');
    let Ok(decoded) = percent_encoding::percent_decode_str(trimmed).decode_utf8() else {
        return Resolved::Refused;
    };
    let mut candidate = root.to_path_buf();
    for component in Path::new(&*decoded).components() {
        match component {
            Component::Normal(c)
                if Path::new(c)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))) =>
            {
                candidate.push(c)
            }
            Component::CurDir => {}
            _ => return Resolved::Refused,
        }
    }
    let Ok(real) = std::fs::canonicalize(&candidate) else {
        return Resolved::Missing;
    };
    if !real.starts_with(root) {
        return Resolved::Refused;
    }
    if real.is_dir() {
        // `ServeDir` appends `index.html` to directory requests.
        return match std::fs::canonicalize(real.join("index.html")) {
            Ok(index) if !index.starts_with(root) => Resolved::Refused,
            Ok(_) => Resolved::File,
            Err(_) => Resolved::Missing,
        };
    }
    Resolved::File
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tower::ServiceExt;

    const EXPECTED_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

    /// `<tmp>/console` is the Console dir; `<tmp>/secret` and
    /// `<tmp>/Cargo.toml` sit just outside it.
    struct Fixture {
        _tmp: tempfile::TempDir,
        console: std::path::PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let console = tmp.path().join("console");
        std::fs::create_dir_all(console.join("assets")).unwrap();
        std::fs::write(
            console.join("index.html"),
            "<!doctype html><title>OSIRIS-INDEX</title>",
        )
        .unwrap();
        std::fs::write(console.join("assets/app-abc.js"), "console.log('app');").unwrap();
        std::fs::write(tmp.path().join("secret"), "OUTSIDE-SECRET").unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "OUTSIDE-SECRET").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(tmp.path().join("secret"), console.join("leak")).unwrap();
        Fixture { _tmp: tmp, console }
    }

    fn app(f: &Fixture) -> Router {
        attach_console(Router::new(), Some(&f.console), false)
    }

    async fn send(
        app: Router,
        method: &str,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let resp = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn header<'a>(h: &'a axum::http::HeaderMap, name: &str) -> &'a str {
        h.get(name)
            .unwrap_or_else(|| panic!("missing header {name}"))
            .to_str()
            .unwrap()
    }

    #[tokio::test]
    async fn root_serves_index_with_security_headers() {
        let f = fixture();
        let (status, h, body) = send(app(&f), "GET", "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("OSIRIS-INDEX"));
        assert_eq!(header(&h, "content-security-policy"), EXPECTED_CSP);
        assert_eq!(header(&h, "x-frame-options"), "DENY");
        assert_eq!(header(&h, "x-content-type-options"), "nosniff");
        assert_eq!(header(&h, "referrer-policy"), "no-referrer");
        assert_eq!(header(&h, "cache-control"), "no-cache");
        assert!(h.get("strict-transport-security").is_none());
    }

    #[tokio::test]
    async fn deep_link_falls_back_to_index() {
        let f = fixture();
        let (status, h, body) = send(app(&f), "GET", "/alerts/123").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("OSIRIS-INDEX"));
        assert_eq!(header(&h, "cache-control"), "no-cache");
        assert_eq!(header(&h, "content-security-policy"), EXPECTED_CSP);
    }

    #[tokio::test]
    async fn asset_is_cacheable() {
        let f = fixture();
        let (status, h, body) = send(app(&f), "GET", "/assets/app-abc.js").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("console.log"));
        assert!(header(&h, "cache-control").contains("immutable"));
        assert_eq!(header(&h, "x-content-type-options"), "nosniff");
    }

    #[tokio::test]
    async fn missing_asset_is_not_cached_as_immutable() {
        let f = fixture();
        let (_, h, _) = send(app(&f), "GET", "/assets/gone-123.js").await;
        assert!(!header(&h, "cache-control").contains("immutable"));
    }

    #[tokio::test]
    async fn unknown_api_path_is_404_not_index() {
        let f = fixture();
        for uri in ["/api/v1/nope", "/api/", "/api"] {
            let (status, _, body) = send(app(&f), "GET", uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(!body.contains("OSIRIS-INDEX"), "{uri}");
        }
    }

    #[tokio::test]
    async fn api_routes_keep_precedence_and_auth() {
        let f = fixture();
        let gated = Router::new()
            .route("/api/v1/secret", get(|| async { "SECRET-DATA" }))
            .layer(axum::middleware::from_fn(
                |_req: Request<Body>, _next: axum::middleware::Next| async {
                    StatusCode::UNAUTHORIZED.into_response()
                },
            ));
        let app = attach_console(gated, Some(&f.console), false);
        let (status, _, body) = send(app.clone(), "GET", "/api/v1/secret").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!body.contains("SECRET-DATA"));
        // The Console itself is served without passing the gate.
        let (status, _, body) = send(app, "GET", "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("OSIRIS-INDEX"));
    }

    #[tokio::test]
    async fn traversal_is_refused() {
        let f = fixture();
        for uri in [
            "/../Cargo.toml",
            "/../secret",
            "/%2e%2e/secret",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/assets/..%2f..%2fsecret",
            "/assets/%2e%2e%2f%2e%2e%2fsecret",
            "/..%5csecret",
            "/%2fetc%2fpasswd",
        ] {
            let (status, _, body) = send(app(&f), "GET", uri).await;
            assert!(!body.contains("OUTSIDE-SECRET"), "{uri} leaked ({status})");
            assert_ne!(status, StatusCode::OK, "{uri}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_out_of_console_dir_is_404() {
        let f = fixture();
        let (status, _, body) = send(app(&f), "GET", "/leak").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("OUTSIDE-SECRET"));
    }

    #[tokio::test]
    async fn post_is_405() {
        let f = fixture();
        let (status, _, body) = send(app(&f), "POST", "/").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(!body.contains("OSIRIS-INDEX"));
    }

    #[tokio::test]
    async fn head_is_served() {
        let f = fixture();
        let (status, h, _) = send(app(&f), "HEAD", "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(header(&h, "cache-control"), "no-cache");
    }

    #[tokio::test]
    async fn missing_index_runs_api_only() {
        let f = fixture();
        std::fs::remove_file(f.console.join("index.html")).unwrap();
        let (status, _, _) = send(app(&f), "GET", "/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = send(app(&f), "GET", "/assets/app-abc.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("console.log"));
    }

    #[tokio::test]
    async fn missing_dir_runs_api_only() {
        let f = fixture();
        let app = attach_console(Router::new(), Some(&f.console.join("nope")), false);
        let (status, _, _) = send(app, "GET", "/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
