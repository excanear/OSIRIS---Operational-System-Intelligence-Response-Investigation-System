//! OTLP/HTTP-JSON and generic NDJSON webhook exporters.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Client, StatusCode, Url};
use sha2::Sha256;

use super::tls::client_tls_config;
use crate::config::{OtlpConfig, WebhookConfig};
use crate::error::{ConfigError, ExportError};
use crate::exporter::{ExportOutcome, Exporter};
use crate::format::{ndjson_line, otlp_logs_body};
use crate::record::ExportRecord;

/// Client, target and static headers shared by both HTTP exporters.
struct HttpSender {
    client: Client,
    url: Url,
    host: String,
    headers: HeaderMap,
}

/// Everything an HTTP exporter needs from its config section.
struct HttpParams<'a> {
    url: &'a str,
    headers_file: Option<&'a Path>,
    ca_file: Option<&'a Path>,
    client_cert: Option<&'a Path>,
    client_key: Option<&'a Path>,
    timeout_secs: u64,
}

impl HttpSender {
    fn new(name: &str, p: HttpParams<'_>) -> Result<Self, ConfigError> {
        let url = Url::parse(p.url).map_err(|_| ConfigError::new(name, "invalid URL"))?;
        let host = url.host_str().unwrap_or_default().to_string();
        let tls = client_tls_config(p.ca_file, p.client_cert, p.client_key)
            .map_err(|e| ConfigError::new(name, e.message))?;
        let client = Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .timeout(Duration::from_secs(p.timeout_secs))
            // A redirect could carry the configured headers to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ConfigError::new(name, "cannot build HTTP client"))?;
        let headers = match p.headers_file {
            Some(path) => read_headers(name, path)?,
            None => HeaderMap::new(),
        };
        Ok(Self {
            client,
            url,
            host,
            headers,
        })
    }

    /// POST `body`; returns the response body of a 2xx reply.
    async fn post(
        &self,
        content_type: &'static str,
        extra: Option<(HeaderName, HeaderValue)>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ExportError> {
        let mut req = self
            .client
            .post(self.url.clone())
            .headers(self.headers.clone())
            .header(CONTENT_TYPE, content_type);
        if let Some((n, v)) = extra {
            req = req.header(n, v);
        }
        let resp = req.body(body).send().await.map_err(|e| {
            // Never `e.to_string()`: reqwest errors may embed the URL.
            let kind = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connect error"
            } else {
                "request error"
            };
            ExportError::Transient(format!("{kind} to {}", self.host))
        })?;
        let status = resp.status();
        if status.is_success() {
            // A body read failure after a 2xx must not fail the delivery.
            return Ok(resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default());
        }
        let msg = format!("{} from {}", status.as_u16(), self.host);
        if status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
        {
            Err(ExportError::Transient(msg))
        } else {
            Err(ExportError::Permanent(msg))
        }
    }
}

impl fmt::Debug for HttpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Headers and the URL query may hold secrets; show only the host.
        f.debug_struct("HttpSender")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// Parse `Name: value` lines. Errors name the line number, never the content.
fn read_headers(name: &str, path: &Path) -> Result<HeaderMap, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::new(
            name,
            format!(
                "cannot read headers_file `{}`: {}",
                path.display(),
                e.kind()
            ),
        )
    })?;
    let mut map = HeaderMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = || ConfigError::new(name, format!("headers_file line {}: invalid header", i + 1));
        let (n, v) = line.split_once(':').ok_or_else(bad)?;
        let n = HeaderName::from_bytes(n.trim().as_bytes()).map_err(|_| bad())?;
        let mut v = HeaderValue::from_str(v.trim()).map_err(|_| bad())?;
        v.set_sensitive(true);
        map.append(n, v);
    }
    Ok(map)
}

fn read_hmac_key(name: &str, path: &Path) -> Result<Vec<u8>, ConfigError> {
    let mut key = std::fs::read(path).map_err(|e| {
        ConfigError::new(
            name,
            format!(
                "cannot read hmac_key_file `{}`: {}",
                path.display(),
                e.kind()
            ),
        )
    })?;
    if key.ends_with(b"\n") {
        key.pop();
        if key.ends_with(b"\r") {
            key.pop();
        }
    }
    if key.is_empty() {
        return Err(ConfigError::new(name, "hmac_key_file is empty"));
    }
    Ok(key)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// `partialSuccess.rejectedLogRecords` (a string or a number) of an OTLP reply.
fn rejected_records(body: &[u8]) -> u64 {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return 0;
    };
    match &v["partialSuccess"]["rejectedLogRecords"] {
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        _ => 0,
    }
}

pub struct OtlpExporter {
    name: String,
    sender: HttpSender,
    include_raw: bool,
}

impl fmt::Debug for OtlpExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpExporter")
            .field("name", &self.name)
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

impl OtlpExporter {
    pub fn new(name: &str, cfg: &OtlpConfig, include_raw: bool) -> Result<Self, ConfigError> {
        let sender = HttpSender::new(
            name,
            HttpParams {
                url: &cfg.endpoint,
                headers_file: cfg.headers_file.as_deref(),
                ca_file: cfg.ca_file.as_deref(),
                client_cert: cfg.client_cert.as_deref(),
                client_key: cfg.client_key.as_deref(),
                timeout_secs: cfg.timeout_secs,
            },
        )?;
        Ok(Self {
            name: name.to_string(),
            sender,
            include_raw,
        })
    }
}

#[async_trait]
impl Exporter for OtlpExporter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError> {
        let body = otlp_logs_body(batch, self.include_raw, now_ns()).to_string();
        let reply = self
            .sender
            .post("application/json", None, body.into_bytes())
            .await?;
        Ok(ExportOutcome {
            dropped: rejected_records(&reply),
            truncated: 0,
        })
    }
}

pub struct WebhookExporter {
    name: String,
    sender: HttpSender,
    include_raw: bool,
    hmac_key: Option<Vec<u8>>,
}

impl fmt::Debug for WebhookExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookExporter")
            .field("name", &self.name)
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

impl WebhookExporter {
    pub fn new(name: &str, cfg: &WebhookConfig, include_raw: bool) -> Result<Self, ConfigError> {
        let sender = HttpSender::new(
            name,
            HttpParams {
                url: &cfg.url,
                headers_file: cfg.headers_file.as_deref(),
                ca_file: cfg.ca_file.as_deref(),
                client_cert: cfg.client_cert.as_deref(),
                client_key: cfg.client_key.as_deref(),
                timeout_secs: cfg.timeout_secs,
            },
        )?;
        let hmac_key = cfg
            .hmac_key_file
            .as_deref()
            .map(|p| read_hmac_key(name, p))
            .transpose()?;
        Ok(Self {
            name: name.to_string(),
            sender,
            include_raw,
            hmac_key,
        })
    }
}

#[async_trait]
impl Exporter for WebhookExporter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError> {
        let mut body = String::new();
        for rec in batch {
            body.push_str(&ndjson_line(rec, self.include_raw));
            body.push('\n');
        }
        let body = body.into_bytes();
        let sig = self.hmac_key.as_ref().and_then(|key| {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).ok()?;
            mac.update(&body);
            let hex = hex::encode(mac.finalize().into_bytes());
            let value = HeaderValue::from_str(&format!("sha256={hex}")).ok()?;
            Some((HeaderName::from_static("x-osiris-signature"), value))
        });
        self.sender.post("application/x-ndjson", sig, body).await?;
        Ok(ExportOutcome::default())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Mutex;

    use axum::body::Bytes;
    use axum::http::HeaderMap as AxHeaders;
    use axum::routing::post;
    use axum::Router;

    use super::*;
    use crate::transport::testutil::event;

    type Captured = (AxHeaders, Vec<u8>);

    #[derive(Clone)]
    struct Rx {
        got: Arc<Mutex<Vec<Captured>>>,
        status: Arc<AtomicU16>,
        reply: Arc<Mutex<String>>,
    }

    async fn receiver() -> (String, Rx) {
        let rx = Rx {
            got: Arc::new(Mutex::new(vec![])),
            status: Arc::new(AtomicU16::new(200)),
            reply: Arc::new(Mutex::new(String::new())),
        };
        let st = rx.clone();
        let app = Router::new().route(
            "/x",
            post(move |h: AxHeaders, b: Bytes| {
                let st = st.clone();
                async move {
                    st.got.lock().unwrap().push((h, b.to_vec()));
                    (
                        axum::http::StatusCode::from_u16(st.status.load(Ordering::SeqCst)).unwrap(),
                        st.reply.lock().unwrap().clone(),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/x"), rx)
    }

    fn tmp(name: &str, content: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "osiris-http-{}-{}-{name}",
            std::process::id(),
            now_ns()
        ));
        std::fs::write(&p, content).unwrap();
        p
    }

    fn wh(url: &str) -> WebhookConfig {
        WebhookConfig {
            url: url.to_string(),
            hmac_key_file: None,
            headers_file: None,
            ca_file: None,
            client_cert: None,
            client_key: None,
            timeout_secs: 5,
        }
    }

    fn otlp(url: &str) -> OtlpConfig {
        OtlpConfig {
            endpoint: url.to_string(),
            headers_file: None,
            ca_file: None,
            client_cert: None,
            client_key: None,
            timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn webhook_posts_ndjson_with_valid_hmac() {
        let (url, rx) = receiver().await;
        let mut cfg = wh(&url);
        cfg.hmac_key_file = Some(tmp("key", b"s3cret-key\r\n"));
        let ex = WebhookExporter::new("w", &cfg, false).unwrap();
        ex.export(&[event(1), event(2)]).await.unwrap();
        let got = rx.got.lock().unwrap();
        let (h, body) = &got[0];
        assert_eq!(h["content-type"], "application/x-ndjson");
        let text = String::from_utf8(body.clone()).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"s3cret-key").unwrap();
        mac.update(body);
        let want = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert_eq!(h["x-osiris-signature"], want.as_str());
    }

    #[tokio::test]
    async fn webhook_without_hmac_has_no_signature_header() {
        let (url, rx) = receiver().await;
        let ex = WebhookExporter::new("w", &wh(&url), false).unwrap();
        ex.export(&[event(1)]).await.unwrap();
        assert!(!rx.got.lock().unwrap()[0]
            .0
            .contains_key("x-osiris-signature"));
    }

    #[tokio::test]
    async fn webhook_sends_headers_from_headers_file() {
        let (url, rx) = receiver().await;
        let mut cfg = wh(&url);
        cfg.headers_file = Some(tmp(
            "hdr",
            b"# comment\n\nAuthorization: Bearer abc\nX-Tenant:  t1 \n",
        ));
        let ex = WebhookExporter::new("w", &cfg, false).unwrap();
        ex.export(&[event(1)]).await.unwrap();
        let got = rx.got.lock().unwrap();
        assert_eq!(got[0].0["authorization"], "Bearer abc");
        assert_eq!(got[0].0["x-tenant"], "t1");
    }

    #[tokio::test]
    async fn status_500_and_429_are_transient_400_is_permanent() {
        let (url, rx) = receiver().await;
        let ex = WebhookExporter::new("w", &wh(&url), false).unwrap();
        for (code, transient) in [(500, true), (429, true), (408, true), (400, false)] {
            rx.status.store(code, Ordering::SeqCst);
            let err = ex.export(&[event(1)]).await.unwrap_err();
            match (&err, transient) {
                (ExportError::Transient(m), true) | (ExportError::Permanent(m), false) => {
                    assert!(m.starts_with(&code.to_string()), "{m}");
                    assert!(m.contains("127.0.0.1"));
                    assert!(!m.contains("/x"));
                }
                _ => panic!("code {code}: {err:?}"),
            }
        }
    }

    #[tokio::test]
    async fn otlp_posts_json_logs_and_counts_partial_success() {
        let (url, rx) = receiver().await;
        *rx.reply.lock().unwrap() = r#"{"partialSuccess":{"rejectedLogRecords":"2"}}"#.into();
        let ex = OtlpExporter::new("o", &otlp(&url), false).unwrap();
        let out = ex.export(&[event(1), event(2)]).await.unwrap();
        assert_eq!(out.dropped, 2);
        {
            let got = rx.got.lock().unwrap();
            assert_eq!(got[0].0["content-type"], "application/json");
            let v: serde_json::Value = serde_json::from_slice(&got[0].1).unwrap();
            assert!(v["resourceLogs"].is_array());
        }
        *rx.reply.lock().unwrap() = r#"{"partialSuccess":{"rejectedLogRecords":3}}"#.into();
        assert_eq!(ex.export(&[event(1)]).await.unwrap().dropped, 3);
        *rx.reply.lock().unwrap() = "{}".into();
        assert_eq!(ex.export(&[event(1)]).await.unwrap().dropped, 0);
    }

    #[tokio::test]
    async fn error_messages_never_contain_url_query_or_header_values() {
        let mut cfg = wh("http://127.0.0.1:1/x?token=SECRET");
        cfg.headers_file = Some(tmp("hdr", b"Authorization: Bearer SECRET\n"));
        cfg.timeout_secs = 2;
        let ex = WebhookExporter::new("w", &cfg, false).unwrap();
        let err = ex.export(&[event(1)]).await.unwrap_err();
        assert!(matches!(err, ExportError::Transient(_)));
        assert!(!err.to_string().contains("SECRET"), "{err}");
        assert!(!format!("{ex:?}").contains("SECRET"));
    }

    #[test]
    fn headers_file_with_bad_line_names_the_line_not_the_value() {
        let mut cfg = wh("http://127.0.0.1:1/x");
        cfg.headers_file = Some(tmp("hdr", b"X-Ok: fine\nBad Name With Spaces: SECRET\n"));
        let err = WebhookExporter::new("w", &cfg, false).unwrap_err();
        assert_eq!(err.name, "w");
        assert!(err.message.contains("line 2"), "{err}");
        assert!(!err.to_string().contains("SECRET"));
        cfg.headers_file = Some(tmp("hdr", b"no colon SECRET\n"));
        let err = WebhookExporter::new("w", &cfg, false).unwrap_err();
        assert!(err.message.contains("line 1") && !err.message.contains("SECRET"));
    }

    #[test]
    fn empty_hmac_key_is_a_config_error() {
        let mut cfg = wh("http://127.0.0.1:1/x");
        cfg.hmac_key_file = Some(tmp("key", b"\n"));
        let err = WebhookExporter::new("w", &cfg, false).unwrap_err();
        assert_eq!(err.name, "w");
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn webhook_client_cert_is_wired_to_tls() {
        // An unreadable client cert must surface under the exporter's own
        // name, proving the mTLS options reach `client_tls_config`.
        let mut cfg = wh("https://example.com/x");
        cfg.client_cert = Some(PathBuf::from("/nonexistent/c.pem"));
        cfg.client_key = Some(PathBuf::from("/nonexistent/k.pem"));
        let err = WebhookExporter::new("w", &cfg, false).unwrap_err();
        assert_eq!(err.name, "w");
        assert!(err.message.contains("c.pem"), "{err}");
    }
}
