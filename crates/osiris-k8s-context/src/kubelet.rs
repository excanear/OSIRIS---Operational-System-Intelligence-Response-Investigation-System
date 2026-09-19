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

fn is_loopback_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// The bearer token may go over verified `https`, or to a loopback host. Plain
/// `http` and `https` with certificate verification disabled both count as
/// unauthenticated transport, so they are loopback-only.
pub(crate) fn token_may_be_sent(url: &reqwest::Url, insecure_skip_verify: bool) -> bool {
    if url.scheme() == "https" && !insecure_skip_verify {
        return true;
    }
    is_loopback_host(url)
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Option<String>, reqwest::Error> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_BODY_LEN as u64)
    {
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
        let mut builder = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .no_proxy()
            // A kubelet never redirects /pods; following one could carry the token elsewhere.
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca_path) = &cfg.ca_path {
            let pem = std::fs::read(ca_path).ok()?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).ok()?);
        }
        if cfg.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
            if is_loopback_host(&url) {
                tracing::warn!("kubelet certificate verification is disabled (insecure_skip_verify); the token is sent only because the kubelet is on loopback");
            } else {
                tracing::warn!("kubelet certificate verification is disabled (insecure_skip_verify) for a non-loopback kubelet; the service-account token will NOT be sent");
            }
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
            send_token: token_may_be_sent(&url, cfg.insecure_skip_verify),
            token_path: cfg.token_path,
            client,
        })
    }

    /// `Some(map)` on success; `None` on any failure (see `fetch_result` for the cause).
    pub async fn fetch(&self) -> Option<HashMap<String, PodRef>> {
        self.fetch_result().await.ok()
    }

    /// Like `fetch`, but the failure reason is returned. The error's `Display`
    /// never contains the service-account token.
    pub async fn fetch_result(&self) -> Result<HashMap<String, PodRef>, FetchError> {
        if !self.send_token {
            return Err(FetchError::TokenNotSendable);
        }
        let token = match std::fs::read_to_string(&self.token_path) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            Ok(_) => return Err(FetchError::TokenFileEmpty),
            Err(e) => return Err(FetchError::TokenFileUnreadable(e.kind().to_string())),
        };
        let resp = self
            .client
            .get(&self.pods_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| FetchError::Request(e.without_url().to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        let body = match read_capped(resp).await {
            Ok(Some(body)) => body,
            Ok(None) => return Err(FetchError::TooLarge),
            Err(e) => return Err(FetchError::Request(e.without_url().to_string())),
        };
        parse_pod_list(&body).ok_or(FetchError::NotAPodList)
    }
}

/// Why a kubelet fetch failed. `Display` is safe to log: it never includes the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    TokenNotSendable,
    TokenFileEmpty,
    TokenFileUnreadable(String),
    Request(String),
    Status(u16),
    TooLarge,
    NotAPodList,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenNotSendable => f.write_str(
                "refusing to send the service-account token (plain http to a non-loopback kubelet, or certificate verification disabled on a non-loopback kubelet)",
            ),
            Self::TokenFileEmpty => f.write_str("the service-account token file is empty"),
            Self::TokenFileUnreadable(k) => write!(f, "could not read the service-account token file ({k})"),
            Self::Request(e) => write!(f, "kubelet request failed: {e}"),
            Self::Status(c) => write!(f, "kubelet returned HTTP status {c}"),
            Self::TooLarge => f.write_str("kubelet response exceeded the size cap"),
            Self::NotAPodList => f.write_str("kubelet response was not a PodList"),
        }
    }
}

impl std::error::Error for FetchError {}

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
        let ok =
            headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected.as_str());
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let status = *mock.status.lock().unwrap();
        (
            StatusCode::from_u16(status).unwrap(),
            mock.body.lock().unwrap().clone(),
        )
            .into_response()
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
        assert!(
            client.fetch().await.is_some(),
            "rotated token must be picked up"
        );
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
        let big = format!(
            r#"{{"items":[],"pad":"{}"}}"#,
            "x".repeat(MAX_BODY_LEN + 10)
        );
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
        listener: tokio::net::TcpListener,
        pods_redirects_to: Option<String>,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
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
                            Some(loc) => (StatusCode::FOUND, [("location", loc)], String::new())
                                .into_response(),
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
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (pods_hits, target_hits)
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
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (pods_hits, _) = counting_server(listener, None).await;
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(&format!("http://{ip}:{port}"), &token_file(&dir, "secret"));
        assert!(client.fetch().await.is_none());
        assert_eq!(
            pods_hits.load(Ordering::SeqCst),
            0,
            "no request may reach a non-loopback http kubelet"
        );
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use std::sync::atomic::Ordering;
        // Bind once and reuse the same listener: no bind/drop/rebind port race.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (pods_hits, target_hits) =
            counting_server(listener, Some(format!("http://127.0.0.1:{port}/target"))).await;
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(&format!("http://127.0.0.1:{port}"), &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
        assert_eq!(pods_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            target_hits.load(Ordering::SeqCst),
            0,
            "the redirect target must never be requested"
        );
    }

    #[test]
    fn token_may_be_sent_over_https_or_to_loopback_only() {
        let ok = |u: &str| token_may_be_sent(&reqwest::Url::parse(u).unwrap(), false);
        assert!(ok("https://10.0.0.5:10250"));
        assert!(ok("https://kubelet.example:10250"));
        assert!(ok("http://127.0.0.1:10255"));
        assert!(ok("http://localhost:10255"));
        assert!(ok("http://[::1]:10255"));
        assert!(!ok("http://10.0.0.5:10255"));
        assert!(!ok("http://kubelet.example:10255"));
    }

    fn client_with(url: &str, insecure: bool) -> KubeletClient {
        KubeletClient::new(KubeletConfig {
            url: url.to_string(),
            token_path: "/t".into(),
            ca_path: None,
            insecure_skip_verify: insecure,
        })
        .expect("client")
    }

    #[test]
    fn insecure_skip_verify_never_sends_the_token_to_a_non_loopback_host() {
        assert!(!client_with("https://10.0.0.5:10250", true).send_token);
        assert!(!client_with("https://kubelet.example:10250", true).send_token);
        assert!(client_with("https://10.0.0.5:10250", false).send_token);
    }

    #[test]
    fn insecure_skip_verify_on_loopback_still_sends_the_token() {
        assert!(client_with("https://127.0.0.1:10250", true).send_token);
        assert!(client_with("https://localhost:10250", true).send_token);
    }

    #[tokio::test]
    async fn fetch_result_reports_a_cause_that_never_contains_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Mock::new("secret-token", POD_LIST);
        let base = serve(mock.clone()).await;
        *mock.status.lock().unwrap() = 500;
        let client = client_for(&base, &token_file(&dir, "secret-token"));
        let err = client.fetch_result().await.unwrap_err();
        assert!(!err.to_string().contains("secret-token"));
        assert!(err.to_string().contains("500"), "{err}");
        let missing = client_for(&base, &dir.path().join("nope"));
        assert!(missing
            .fetch_result()
            .await
            .unwrap_err()
            .to_string()
            .contains("token file"));
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
        assert!(
            KubeletClient::new(base("https://127.0.0.1:10250", Some("/no/such/ca.pem"))).is_none()
        );
        assert!(KubeletClient::new(base("https://127.0.0.1:10250", None)).is_some());
    }
}
