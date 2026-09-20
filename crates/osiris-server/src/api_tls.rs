//! Native TLS for the API/Console listener (Phase 9b).
//!
//! `serve_tls` terminates TLS 1.3 (ALPN `h2`/`http/1.1`) in front of the axum
//! `Router`. Connections are capped globally and per peer IP, handshakes and
//! request headers are time-limited, and cancelling the token drains open
//! connections gracefully (bounded).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Handshakes that take longer than this are dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// A request's headers must arrive within this time (also bounds idle keep-alive).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 1024;
const MAX_CONNECTIONS_PER_IP: usize = 16;
const HSTS_VALUE: &str = "max-age=31536000";

#[derive(Debug, thiserror::Error)]
pub enum ApiTlsError {
    #[error("api_tls cert/key unusable: {0}")]
    Config(#[from] osiris_transport::tls::TlsError),
}

/// Builds the TLS acceptor, failing on an unreadable or invalid cert/key.
pub fn acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, ApiTlsError> {
    warn_if_key_is_readable(key);
    Ok(TlsAcceptor::from(
        osiris_transport::tls::server_config_no_client_auth(cert, key)?,
    ))
}

/// Warns when the private key is accessible to group/other (unix only).
fn warn_if_key_is_readable(key: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(key) {
            if m.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    key = %key.display(),
                    "api_tls key file is accessible to group/other; restrict it to mode 0600"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = key;
}

/// Adds `Strict-Transport-Security` to every response. Apply only when TLS is active.
pub fn with_hsts(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(
        |req: Request<Body>, next: Next| async move {
            let mut resp: Response = next.run(req).await;
            resp.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static(HSTS_VALUE),
            );
            resp
        },
    ))
}

/// True when `listen_addr` parses as a loopback socket address, or is
/// `localhost:<port>`.
pub fn is_loopback_addr(listen_addr: &str) -> bool {
    match listen_addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a.ip().is_loopback(),
        Err(_) => listen_addr
            .rsplit_once(':')
            .map(|(h, _)| h == "localhost")
            .unwrap_or(false),
    }
}

/// Resource limits for the TLS listener.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_connections: usize,
    pub max_per_ip: usize,
    pub handshake_timeout: Duration,
    /// A client must deliver each request's headers within this time.
    pub header_read_timeout: Duration,
    /// How long open connections may take to finish after shutdown.
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_per_ip: MAX_CONNECTIONS_PER_IP,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            header_read_timeout: HEADER_READ_TIMEOUT,
            shutdown_grace: SHUTDOWN_GRACE,
        }
    }
}

/// Tracks concurrent connections per peer IP; dropping the guard releases the slot.
#[derive(Default)]
struct IpCounter(Mutex<HashMap<IpAddr, usize>>);

struct IpGuard {
    counter: Arc<IpCounter>,
    ip: IpAddr,
}

impl IpCounter {
    fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<IpGuard> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpGuard {
            counter: self.clone(),
            ip,
        })
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self.counter.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Serves `router` over TLS on `listener` until `shutdown` is cancelled.
pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    shutdown: CancellationToken,
) {
    serve_tls_with(listener, acceptor, router, shutdown, Limits::default()).await
}

/// [`serve_tls`] with explicit [`Limits`].
pub async fn serve_tls_with(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    shutdown: CancellationToken,
    limits: Limits,
) {
    let router = with_hsts(router);
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let per_ip = Arc::new(IpCounter::default());
    loop {
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "api accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "api listener at its connection limit; refusing");
            continue;
        };
        let Some(ip_guard) = per_ip.acquire(peer.ip(), limits.max_per_ip) else {
            tracing::warn!(%peer, "too many concurrent api connections from this address; refusing");
            continue;
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ip_guard = ip_guard;
            let tls =
                match tokio::time::timeout(limits.handshake_timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::debug!(%peer, error = %e, "api tls handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%peer, "api tls handshake timed out");
                        return;
                    }
                };
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let router = router.clone();
                async move { router.oneshot(req.map(Body::new)).await }
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read_timeout);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
                .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT);
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            tokio::pin!(conn);
            let mut draining = false;
            let grace = tokio::time::sleep(Duration::MAX / 4);
            tokio::pin!(grace);
            loop {
                tokio::select! {
                    r = conn.as_mut() => {
                        if let Err(e) = r {
                            tracing::debug!(%peer, error = %e, "api connection ended with error");
                        }
                        break;
                    }
                    _ = shutdown.cancelled(), if !draining => {
                        draining = true;
                        conn.as_mut().graceful_shutdown();
                        grace.as_mut().reset(tokio::time::Instant::now() + limits.shutdown_grace);
                    }
                    _ = &mut grace, if draining => break,
                }
            }
        });
    }
    // Let in-flight connections finish (bounded).
    let _ = tokio::time::timeout(
        limits.shutdown_grace + Duration::from_secs(1),
        permits.acquire_many(limits.max_connections as u32),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use futures_util::StreamExt;
    use osiris_auth::UserStore;
    use osiris_transport::pki;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    struct Certs {
        _dir: tempfile::TempDir,
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
        ca_pem: String,
    }

    fn certs() -> Certs {
        let dir = tempfile::tempdir().unwrap();
        let ca = pki::generate_ca("test-ca").unwrap();
        let srv = pki::issue_server(
            &ca.cert_pem,
            &ca.key_pem,
            &["localhost".to_string(), "127.0.0.1".to_string()],
        )
        .unwrap();
        pki::write_issued(dir.path(), "api", &srv).unwrap();
        Certs {
            cert: dir.path().join("api.pem"),
            key: dir.path().join("api.key"),
            ca_pem: ca.cert_pem,
            _dir: dir,
        }
    }

    fn connector(ca_pem: Option<&str>, alpn: &[&[u8]]) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(pem) = ca_pem {
            for c in rustls_pemfile_certs(pem) {
                roots.add(c).unwrap();
            }
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        TlsConnector::from(Arc::new(cfg))
    }

    fn rustls_pemfile_certs(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), pem).unwrap();
        osiris_transport::tls::load_certs(f.path()).unwrap()
    }

    struct Server {
        addr: std::net::SocketAddr,
        token: CancellationToken,
        session: String,
        _dir: tempfile::TempDir,
    }

    /// The real layered composition from main.rs: stream + auth routers, the
    /// `auth_gate` layer, and (inside `serve_tls`) the HSTS layer.
    fn gated_app() -> (Router, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (users, _bootstrap) =
            osiris_auth::SqliteUserStore::open(dir.path().join("users.db")).unwrap();
        let admin = users.get_user_by_username("admin").unwrap().unwrap();
        let session = users.create_session(admin.user_id, 3600).unwrap().token;
        let state = osiris_api::AuthState {
            users: Arc::new(users),
            audit_log: Arc::new(
                osiris_audit::FileAuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
            ),
            session_ttl_seconds: 3600,
            tenants: Arc::new(
                osiris_tenancy::SqliteTenantStore::open(dir.path().join("tenants.db")).unwrap(),
            ),
        };
        let app =
            osiris_api::build_stream_router(Arc::new(osiris_api::LiveEventBroadcaster::new()))
                .route("/api/v1/health", get(|| async { "pong" }))
                .merge(osiris_api::build_auth_router(state.clone()))
                .layer(axum::middleware::from_fn_with_state(
                    state,
                    osiris_api::auth_gate,
                ));
        (app, session, dir)
    }

    async fn start(c: &Certs) -> Server {
        start_with(c, Limits::default()).await
    }

    async fn start_with(c: &Certs, limits: Limits) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let (app, session, dir) = gated_app();
        tokio::spawn(serve_tls_with(
            listener,
            acceptor(&c.cert, &c.key).unwrap(),
            app,
            token.clone(),
            limits,
        ));
        Server {
            addr,
            token,
            session,
            _dir: dir,
        }
    }

    async fn https_get(addr: std::net::SocketAddr, ca: Option<&str>) -> std::io::Result<String> {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let mut s = connector(ca, &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        s.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut out = String::new();
        s.read_to_string(&mut out).await.ok();
        Ok(out)
    }

    #[tokio::test]
    async fn https_with_ca_succeeds_and_carries_hsts() {
        let c = certs();
        let srv = start(&c).await;
        let resp = https_get(srv.addr, Some(&c.ca_pem)).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp
            .to_lowercase()
            .contains("strict-transport-security: max-age=31536000"));
        assert!(resp.ends_with("pong"));
        srv.token.cancel();
    }

    #[tokio::test]
    async fn client_without_the_ca_is_rejected() {
        let c = certs();
        let srv = start(&c).await;
        assert!(https_get(srv.addr, None).await.is_err());
        // The server is unaffected by the failed handshake.
        assert!(https_get(srv.addr, Some(&c.ca_pem)).await.is_ok());
        srv.token.cancel();
    }

    #[tokio::test]
    async fn plain_http_to_the_tls_port_fails() {
        let c = certs();
        let srv = start(&c).await;
        let mut tcp = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        tcp.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        // Definite failure: the server ends the connection promptly (close or
        // reset) instead of hanging, and never answers in HTTP.
        let _ = tokio::time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut buf))
            .await
            .expect("server must close the connection, not hang");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            !text.contains("pong") && !text.contains("HTTP/1.1"),
            "{text}"
        );
        srv.token.cancel();
    }

    #[tokio::test]
    async fn alpn_negotiates_h2() {
        let c = certs();
        let srv = start(&c).await;
        let tcp = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        let s = connector(Some(&c.ca_pem), &[b"h2", b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        srv.token.cancel();
    }

    #[test]
    fn bad_cert_path_is_a_setup_error() {
        let r = acceptor(
            Path::new("/nonexistent/c.pem"),
            Path::new("/nonexistent/k.pem"),
        );
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn hsts_layer_adds_the_header_and_plain_router_does_not() {
        let plain = Router::new().route("/p", get(|| async { "x" }));
        let req = || Request::builder().uri("/p").body(Body::empty()).unwrap();
        let r = plain.clone().oneshot(req()).await.unwrap();
        assert!(r.headers().get(header::STRICT_TRANSPORT_SECURITY).is_none());
        let r = with_hsts(plain).oneshot(req()).await.unwrap();
        assert_eq!(
            r.headers().get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            HSTS_VALUE
        );
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_addr("127.0.0.1:8080"));
        assert!(is_loopback_addr("[::1]:8080"));
        assert!(is_loopback_addr("localhost:8080"));
        assert!(!is_loopback_addr("0.0.0.0:8080"));
        assert!(!is_loopback_addr("10.1.2.3:8080"));
    }

    type WsResult = Result<
        tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
        tokio_tungstenite::tungstenite::Error,
    >;

    async fn ws_connect(
        addr: std::net::SocketAddr,
        ca: &str,
        origin: Option<&str>,
        token: Option<&str>,
    ) -> WsResult {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector(Some(ca), &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let q = token.map(|t| format!("?token={t}")).unwrap_or_default();
        let mut req = format!("wss://localhost:{}/api/v1/stream/events{q}", addr.port())
            .into_client_request()
            .unwrap();
        if let Some(o) = origin {
            req.headers_mut().insert("Origin", o.parse().unwrap());
        }
        let (mut ws, resp) = tokio_tungstenite::client_async(req, tls).await?;
        let _ = ws.close(None).await;
        let _ = ws.next().await;
        Ok(resp)
    }

    fn status_of(r: WsResult) -> u16 {
        match r {
            Ok(resp) => resp.status().as_u16(),
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) => r.status().as_u16(),
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_over_tls_honours_auth_gate_and_origin_check() {
        let c = certs();
        let srv = start(&c).await;
        let (addr, tok) = (srv.addr, srv.session.clone());
        let same = format!("https://localhost:{}", addr.port());
        // No token: the auth gate rejects the upgrade.
        assert_eq!(
            status_of(ws_connect(addr, &c.ca_pem, None, None).await),
            401
        );
        // ?token= succeeds (with and without a same-site Origin).
        assert_eq!(
            status_of(ws_connect(addr, &c.ca_pem, Some(&same), Some(&tok)).await),
            101
        );
        assert_eq!(
            status_of(ws_connect(addr, &c.ca_pem, None, Some(&tok)).await),
            101
        );
        // Cross-origin is refused even with a valid token.
        assert_eq!(
            status_of(ws_connect(addr, &c.ca_pem, Some("https://evil.example"), Some(&tok)).await),
            403
        );
        srv.token.cancel();
    }

    #[tokio::test]
    async fn rest_over_tls_requires_a_token_and_carries_hsts() {
        let c = certs();
        let srv = start(&c).await;
        let tcp = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        let mut s = connector(Some(&c.ca_pem), &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        s.write_all(
            b"GET /api/v1/stream/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.ok();
        assert!(out.starts_with("HTTP/1.1 401"), "{out}");
        assert!(out.to_lowercase().contains("strict-transport-security"));
        srv.token.cancel();
    }

    async fn assert_dropped(addr: std::net::SocketAddr) {
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf))
            .await
            .expect("over-cap connection must be dropped promptly");
        assert!(matches!(r, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn per_ip_cap_is_enforced() {
        let c = certs();
        let srv = start_with(
            &c,
            Limits {
                max_per_ip: 2,
                handshake_timeout: Duration::from_secs(30),
                ..Limits::default()
            },
        )
        .await;
        let _a = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        let _b = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_dropped(srv.addr).await;
        srv.token.cancel();
    }

    #[tokio::test]
    async fn global_cap_is_enforced() {
        let c = certs();
        let srv = start_with(
            &c,
            Limits {
                max_connections: 1,
                handshake_timeout: Duration::from_secs(30),
                ..Limits::default()
            },
        )
        .await;
        let _a = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_dropped(srv.addr).await;
        srv.token.cancel();
    }

    #[tokio::test]
    async fn slow_header_client_is_dropped() {
        let c = certs();
        let srv = start_with(
            &c,
            Limits {
                header_read_timeout: Duration::from_millis(300),
                ..Limits::default()
            },
        )
        .await;
        let tcp = tokio::net::TcpStream::connect(srv.addr).await.unwrap();
        let mut s = connector(Some(&c.ca_pem), &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        // Start a request but never finish the headers.
        s.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: loc")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
            .await
            .expect("slow-header connection must be dropped by the server");
        assert!(!String::from_utf8_lossy(&out).contains("pong"));
        srv.token.cancel();
    }

    #[tokio::test]
    async fn cancelling_shuts_the_listener_down() {
        let c = certs();
        let srv = start(&c).await;
        assert!(https_get(srv.addr, Some(&c.ca_pem)).await.is_ok());
        srv.token.cancel();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(tokio::net::TcpStream::connect(srv.addr).await.is_err());
    }
}
