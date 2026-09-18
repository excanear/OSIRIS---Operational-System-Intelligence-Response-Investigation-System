use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use osiris_schema::PodRef;

use crate::parse::parse_pod_list;

/// Largest kubelet `/pods` body accepted. Over the cap the whole fetch fails
/// (never a truncated parse).
pub const MAX_BODY_LEN: usize = 8 * 1024 * 1024;
/// Per-request timeout.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct KubeletConfig {
    /// Base URL, e.g. `https://127.0.0.1:10250`.
    pub url: String,
    /// Service-account token file, re-read on every fetch (projected tokens rotate).
    pub token_path: PathBuf,
    /// Extra root CA (PEM) to trust for the kubelet's serving certificate.
    pub ca_path: Option<PathBuf>,
    /// Opt-in: accept any kubelet certificate. Documented risk; default false.
    pub insecure_skip_verify: bool,
}

/// Fetches `GET <url>/pods` from the node's kubelet.
pub struct KubeletClient {
    pods_url: String,
    send_token: bool,
    token_path: PathBuf,
    client: reqwest::Client,
}

/// The bearer token may go over `https`, or over `http` only to a loopback host.
pub(crate) fn token_may_be_sent(url: &reqwest::Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Option<String>, reqwest::Error> {
    if resp.content_length().is_some_and(|n| n > MAX_BODY_LEN as u64) {
        return Ok(None);
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > MAX_BODY_LEN {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

impl KubeletClient {
    /// `None` when the URL is not http(s), the CA file is unreadable/invalid,
    /// or the HTTP client cannot be built — never a fallback to a default
    /// (proxy-honouring, unbounded) client.
    pub fn new(cfg: KubeletConfig) -> Option<Self> {
        let url = reqwest::Url::parse(&cfg.url).ok()?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return None;
        }
        let mut builder = reqwest::Client::builder().timeout(FETCH_TIMEOUT)
            .no_proxy()
            // A kubelet never redirects /pods; following one could carry the token elsewhere.
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca_path) = &cfg.ca_path {
            let pem = std::fs::read(ca_path).ok()?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).ok()?);
        }
        if cfg.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = match builder.build() {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %e, "could not build the kubelet HTTP client; pod context disabled");
                return None;
            }
        };
        Some(Self {
            pods_url: format!("{}/pods", url.as_str().trim_end_matches('/')),
            send_token: token_may_be_sent(&url),
            token_path: cfg.token_path,
            client,
        })
    }

    /// `Some(map)` on success; `None` (with a debug log) on any failure.
    pub async fn fetch(&self) -> Option<HashMap<String, PodRef>> {
        if !self.send_token {
            tracing::debug!("refusing to send the service-account token over plain http to a non-loopback kubelet");
            return None;
        }
        let token = match std::fs::read_to_string(&self.token_path) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            Ok(_) => {
                tracing::debug!("kubelet token file is empty");
                return None;
            }
            Err(e) => {
                tracing::debug!(error = %e, "could not read the kubelet token file");
                return None;
            }
        };
        let resp = match self.client.get(&self.pods_url).bearer_auth(&token).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "kubelet request failed");
                return None;
            }
        };
        let resp = match resp.error_for_status() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "kubelet returned an error status");
                return None;
            }
        };
        let body = match read_capped(resp).await {
            Ok(Some(body)) => body,
            Ok(None) => {
                tracing::debug!("kubelet response exceeded the size cap");
                return None;
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed reading the kubelet response");
                return None;
            }
        };
        let parsed = parse_pod_list(&body);
        if parsed.is_none() {
            tracing::debug!("kubelet response was not a PodList");
        }
        parsed
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    use super::*;

    const POD_LIST: &str = r#"{"items":[{"metadata":{"name":"web-0","namespace":"prod"},"status":{"containerStatuses":[{"containerID":"containerd://abc"}]}}]}"#;

    #[derive(Clone)]
    pub(crate) struct Mock {
        pub expected_token: Arc<Mutex<String>>,
        pub body: Arc<Mutex<String>>,
        pub status: Arc<Mutex<u16>>,
    }

    impl Mock {
        pub(crate) fn new(token: &str, body: &str) -> Self {
            Self {
                expected_token: Arc::new(Mutex::new(token.to_string())),
                body: Arc::new(Mutex::new(body.to_string())),
                status: Arc::new(Mutex::new(200)),
            }
        }
    }

    async fn pods(State(mock): State<Mock>, headers: HeaderMap) -> impl IntoResponse {
        let expected = format!("Bearer {}", mock.expected_token.lock().unwrap());
        let ok = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected.as_str());
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let status = *mock.status.lock().unwrap();
        (StatusCode::from_u16(status).unwrap(), mock.body.lock().unwrap().clone()).into_response()
    }

    pub(crate) async fn serve(mock: Mock) -> String {
        let router = Router::new().route("/pods", get(pods)).with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    pub(crate) fn client_for(url: &str, token_file: &std::path::Path) -> KubeletClient {
        KubeletClient::new(KubeletConfig {
            url: url.to_string(),
            token_path: token_file.to_path_buf(),
            ca_path: None,
            insecure_skip_verify: false,
        })
        .expect("client")
    }

    fn token_file(dir: &tempfile::TempDir, token: &str) -> std::path::PathBuf {
        let path = dir.path().join("token");
        std::fs::write(&path, token).unwrap();
        path
    }

    #[tokio::test]
    async fn fetch_sends_the_bearer_token_and_parses_the_pod_list() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve(Mock::new("tok-1", POD_LIST)).await;
        let client = client_for(&base, &token_file(&dir, "tok-1\n"));
        let map = client.fetch().await.unwrap();
        assert_eq!(map.get("abc").unwrap().pod_name, "web-0");
        assert_eq!(map.get("abc").unwrap().namespace, "prod");
    }

    #[tokio::test]
    async fn wrong_token_is_a_401_and_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve(Mock::new("right", POD_LIST)).await;
        let client = client_for(&base, &token_file(&dir, "wrong"));
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn the_token_file_is_reread_on_every_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_file(&dir, "old");
        let mock = Mock::new("old", POD_LIST);
        let base = serve(mock.clone()).await;
        let client = client_for(&base, &path);
        assert!(client.fetch().await.is_some());

        *mock.expected_token.lock().unwrap() = "new".to_string();
        assert!(client.fetch().await.is_none(), "stale token must fail");
        std::fs::write(&path, "new").unwrap();
        assert!(client.fetch().await.is_some(), "rotated token must be picked up");
    }

    #[tokio::test]
    async fn non_2xx_malformed_json_and_missing_token_file_yield_none() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Mock::new("t", POD_LIST);
        let base = serve(mock.clone()).await;
        let client = client_for(&base, &token_file(&dir, "t"));

        *mock.status.lock().unwrap() = 500;
        assert!(client.fetch().await.is_none());
        *mock.status.lock().unwrap() = 200;

        *mock.body.lock().unwrap() = "not json".to_string();
        assert!(client.fetch().await.is_none());

        let missing = client_for(&base, &dir.path().join("no-such-token"));
        assert!(missing.fetch().await.is_none());
    }

    #[tokio::test]
    async fn an_over_cap_body_is_a_failure_never_a_truncated_parse() {
        let dir = tempfile::tempdir().unwrap();
        // A valid PodList prefix followed by padding past the cap: a truncated
        // parse would look valid, so the cap must fail the whole fetch.
        let big = format!(r#"{{"items":[],"pad":"{}"}}"#, "x".repeat(MAX_BODY_LEN + 10));
        let base = serve(Mock::new("t", &big)).await;
        let client = client_for(&base, &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_kubelet_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for("http://127.0.0.1:1", &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
    }

    /// Spawns a server on `bind` whose `/pods` and `/target` routes count hits.
    async fn counting_server(
        bind: &str,
        pods_redirects_to: Option<String>,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pods_hits = Arc::new(AtomicUsize::new(0));
        let target_hits = Arc::new(AtomicUsize::new(0));
        let (p, t) = (pods_hits.clone(), target_hits.clone());
        let router = Router::new()
            .route(
                "/pods",
                get(move || {
                    let p = p.clone();
                    let redirect = pods_redirects_to.clone();
                    async move {
                        p.fetch_add(1, Ordering::SeqCst);
                        match redirect {
                            Some(loc) => (StatusCode::FOUND, [("location", loc)], String::new()).into_response(),
                            None => POD_LIST.into_response(),
                        }
                    }
                }),
            )
            .route(
                "/target",
                get(move || {
                    let t = t.clone();
                    async move {
                        t.fetch_add(1, Ordering::SeqCst);
                        POD_LIST
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (addr, pods_hits, target_hits)
    }

    #[tokio::test]
    async fn the_token_is_never_sent_over_plain_http_to_a_non_loopback_host() {
        use std::sync::atomic::Ordering;
        // Find this machine's non-loopback address (no packet is sent).
        let Some(ip) = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
            .and_then(|s| s.local_addr())
            .ok()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        else {
            eprintln!("no non-loopback interface; skipping");
            return;
        };
        let (addr, pods_hits, _) = counting_server("0.0.0.0:0", None).await;
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(&format!("http://{ip}:{}", addr.port()), &token_file(&dir, "secret"));
        assert!(client.fetch().await.is_none());
        assert_eq!(pods_hits.load(Ordering::SeqCst), 0, "no request may reach a non-loopback http kubelet");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (_, pods_hits, target_hits) =
            counting_server(&format!("127.0.0.1:{port}"), Some(format!("http://127.0.0.1:{port}/target"))).await;
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(&format!("http://127.0.0.1:{port}"), &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
        assert_eq!(pods_hits.load(Ordering::SeqCst), 1);
        assert_eq!(target_hits.load(Ordering::SeqCst), 0, "the redirect target must never be requested");
    }

    #[test]
    fn token_may_be_sent_over_https_or_to_loopback_only() {
        let ok = |u: &str| token_may_be_sent(&reqwest::Url::parse(u).unwrap());
        assert!(ok("https://10.0.0.5:10250"));
        assert!(ok("https://kubelet.example:10250"));
        assert!(ok("http://127.0.0.1:10255"));
        assert!(ok("http://localhost:10255"));
        assert!(ok("http://[::1]:10255"));
        assert!(!ok("http://10.0.0.5:10255"));
        assert!(!ok("http://kubelet.example:10255"));
    }

    #[test]
    fn new_rejects_bad_config() {
        let base = |url: &str, ca: Option<&str>| KubeletConfig {
            url: url.to_string(),
            token_path: "/t".into(),
            ca_path: ca.map(Into::into),
            insecure_skip_verify: false,
        };
        assert!(KubeletClient::new(base("not a url", None)).is_none());
        assert!(KubeletClient::new(base("ftp://x", None)).is_none());
        assert!(KubeletClient::new(base("https://127.0.0.1:10250", Some("/no/such/ca.pem"))).is_none());
        assert!(KubeletClient::new(base("https://127.0.0.1:10250", None)).is_some());
    }
}
