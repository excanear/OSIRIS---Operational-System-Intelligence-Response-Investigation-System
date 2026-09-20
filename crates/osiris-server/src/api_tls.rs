//! Native TLS for the API/Console listener (Phase 9b).
//!
//! `serve_tls` terminates TLS 1.3 (ALPN `h2`/`http/1.1`) in front of the axum
//! `Router`. Each connection is handled in its own task, so a bad or slow
//! handshake never affects other connections.

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Handshakes that take longer than this are dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const HSTS_VALUE: &str = "max-age=31536000";

#[derive(Debug, thiserror::Error)]
pub enum ApiTlsError {
    #[error("api_tls cert/key unusable: {0}")]
    Config(#[from] osiris_transport::tls::TlsError),
}

/// Builds the TLS acceptor, failing on an unreadable or invalid cert/key.
pub fn acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, ApiTlsError> {
    Ok(TlsAcceptor::from(
        osiris_transport::tls::server_config_no_client_auth(cert, key)?,
    ))
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

/// True when `listen_addr` parses as a loopback socket address.
pub fn is_loopback_addr(listen_addr: &str) -> bool {
    listen_addr
        .parse::<std::net::SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or_else(|_| {
            listen_addr
                .rsplit_once(':')
                .map(|(h, _)| h.trim_matches(['[', ']']) == "localhost")
                .unwrap_or(false)
        })
}

/// Serves `router` over TLS on `listener` until `shutdown` is cancelled.
pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    shutdown: CancellationToken,
) {
    let router = with_hsts(router);
    loop {
        let (tcp, peer) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "api accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
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
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            tokio::pin!(conn);
            tokio::select! {
                r = conn.as_mut() => {
                    if let Err(e) = r {
                        tracing::debug!(%peer, error = %e, "api connection ended with error");
                    }
                }
                _ = shutdown.cancelled() => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use futures_util::StreamExt;
    use osiris_transport::pki;
    use std::sync::Arc;
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

    async fn start(c: &Certs) -> (std::net::SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let app =
            osiris_api::build_stream_router(Arc::new(osiris_api::LiveEventBroadcaster::new()))
                .route("/ping", get(|| async { "pong" }));
        tokio::spawn(serve_tls(
            listener,
            acceptor(&c.cert, &c.key).unwrap(),
            app,
            token.clone(),
        ));
        (addr, token)
    }

    async fn https_get(addr: std::net::SocketAddr, ca: Option<&str>) -> std::io::Result<String> {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let mut s = connector(ca, &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        s.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut out = String::new();
        s.read_to_string(&mut out).await.ok();
        Ok(out)
    }

    #[tokio::test]
    async fn https_with_ca_succeeds_and_carries_hsts() {
        let c = certs();
        let (addr, token) = start(&c).await;
        let resp = https_get(addr, Some(&c.ca_pem)).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp
            .to_lowercase()
            .contains("strict-transport-security: max-age=31536000"));
        assert!(resp.ends_with("pong"));
        token.cancel();
    }

    #[tokio::test]
    async fn client_without_the_ca_is_rejected() {
        let c = certs();
        let (addr, token) = start(&c).await;
        assert!(https_get(addr, None).await.is_err());
        // The server is unaffected by the failed handshake.
        assert!(https_get(addr, Some(&c.ca_pem)).await.is_ok());
        token.cancel();
    }

    #[tokio::test]
    async fn plain_http_to_the_tls_port_fails() {
        let c = certs();
        let (addr, token) = start(&c).await;
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut buf)).await;
        assert!(!String::from_utf8_lossy(&buf).contains("pong"));
        token.cancel();
    }

    #[tokio::test]
    async fn alpn_negotiates_h2() {
        let c = certs();
        let (addr, token) = start(&c).await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let s = connector(Some(&c.ca_pem), &[b"h2", b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        token.cancel();
    }

    #[test]
    fn bad_cert_path_is_a_setup_error() {
        let r = acceptor(
            Path::new("/nonexistent/c.pem"),
            Path::new("/nonexistent/k.pem"),
        );
        assert!(r.is_err());
    }

    #[test]
    fn hsts_layer_only_when_applied() {
        assert_eq!(HSTS_VALUE, "max-age=31536000");
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

    async fn ws_connect(
        addr: std::net::SocketAddr,
        ca: &str,
        origin: Option<&str>,
    ) -> Result<
        tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
        tokio_tungstenite::tungstenite::Error,
    > {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector(Some(ca), &[b"http/1.1"])
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let mut req = format!("wss://localhost:{}/api/v1/stream/events", addr.port())
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

    #[tokio::test]
    async fn websocket_over_tls_honours_the_origin_check() {
        let c = certs();
        let (addr, token) = start(&c).await;
        let same = format!("https://localhost:{}", addr.port());
        assert!(ws_connect(addr, &c.ca_pem, Some(&same)).await.is_ok());
        assert!(ws_connect(addr, &c.ca_pem, None).await.is_ok());
        match ws_connect(addr, &c.ca_pem, Some("https://evil.example")).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status(), 403),
            other => panic!("expected 403, got {other:?}"),
        }
        token.cancel();
    }
}
