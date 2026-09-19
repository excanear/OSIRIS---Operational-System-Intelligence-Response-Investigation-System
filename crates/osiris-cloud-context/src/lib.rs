//! Optional Cloud context enrichment (ARCHITECTURE.md §21.4). Probes the
//! instance metadata service once at Agent startup; any failure leaves
//! `HostRef.cloud` as `None`, never a startup failure.

use std::time::Duration;

use async_trait::async_trait;
use osiris_schema::CloudContext;

mod aws;
mod azure;
mod gcp;

pub use aws::AwsImdsV2;
pub use azure::AzureImds;
pub use gcp::GcpMetadata;

/// Per-provider budget for the whole probe flow (AWS's two requests share it).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest string field kept from an (untrusted) metadata response.
pub const MAX_FIELD_LEN: usize = 128;

#[async_trait]
pub trait CloudMetadataProvider: Send + Sync {
    /// `Some` only if this provider's metadata service answered with at
    /// least one usable field.
    async fn probe(&self) -> Option<CloudContext>;
}

/// Invisible/bidirectional formatting characters that can make a value render
/// differently from what it contains (spoofing in the Console).
fn is_invisible_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// Trims, rejects control and invisible/bidi characters (-> `None`), truncates to `MAX_FIELD_LEN`.
pub fn sanitize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_control() || is_invisible_format(c))
    {
        return None;
    }
    Some(trimmed.chars().take(MAX_FIELD_LEN).collect())
}

/// IMDS must never go through an HTTP proxy, and must fail fast. Never falls
/// back to a default client (it would proxy and have no timeout, leaking the
/// IMDS token): on build failure returns `None` and providers probe to `None`.
pub(crate) fn http_client() -> Option<reqwest::Client> {
    match reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .no_proxy()
        .build()
    {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "cloud metadata http client build failed; probing disabled");
            None
        }
    }
}

/// Largest metadata response body we will read.
pub(crate) const MAX_BODY_LEN: usize = 64 * 1024;

/// Reads a body, returning `None` (never a truncated prefix) when it exceeds
/// `MAX_BODY_LEN`, so an oversized body is never parsed as if it were valid.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
) -> Result<Option<String>, reqwest::Error> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_BODY_LEN as u64)
    {
        tracing::debug!("metadata response exceeds size cap");
        return Ok(None);
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > MAX_BODY_LEN {
            tracing::debug!("metadata response exceeds size cap");
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Whether `raw` is an acceptable metadata endpoint override: an http(s) URL
/// with a host, no embedded credentials, query or fragment.
pub fn valid_base_url(raw: &str) -> bool {
    match reqwest::Url::parse(raw) {
        Ok(u) => {
            (u.scheme() == "http" || u.scheme() == "https")
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        }
        Err(_) => false,
    }
}

/// Probes every provider concurrently, each under `PROBE_TIMEOUT`, and returns
/// as soon as ANY provider answers: a non-cloud host still waits out the
/// timeouts, but a cloud host no longer waits for the slower non-matching
/// providers. Only one cloud's metadata service can genuinely answer, so which
/// responder wins when several do is unspecified.
pub async fn detect(providers: Vec<Box<dyn CloudMetadataProvider>>) -> Option<CloudContext> {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    let mut probes: FuturesUnordered<_> = providers
        .iter()
        .map(|p| async move {
            tokio::time::timeout(PROBE_TIMEOUT, p.probe())
                .await
                .ok()
                .flatten()
        })
        .collect();
    while let Some(result) = probes.next().await {
        if result.is_some() {
            return result;
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod test_util;

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Option<CloudContext>);
    #[async_trait]
    impl CloudMetadataProvider for Fixed {
        async fn probe(&self) -> Option<CloudContext> {
            self.0.clone()
        }
    }

    struct Slow;
    #[async_trait]
    impl CloudMetadataProvider for Slow {
        async fn probe(&self) -> Option<CloudContext> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(ctx("slow"))
        }
    }

    fn ctx(provider: &str) -> CloudContext {
        CloudContext {
            provider: provider.to_string(),
            instance_id: Some("i-1".into()),
            region: None,
        }
    }

    #[test]
    fn valid_base_url_accepts_plain_http_urls_and_rejects_the_rest() {
        assert!(valid_base_url("http://169.254.169.254"));
        assert!(valid_base_url("https://imds.internal:8443/base"));
        assert!(!valid_base_url("ftp://x"));
        assert!(!valid_base_url("not a url"));
        assert!(!valid_base_url("http://user:pw@host"));
        assert!(!valid_base_url("http://host/?q=1"));
        assert!(!valid_base_url("file:///etc/passwd"));
    }

    #[tokio::test]
    async fn detect_returns_without_waiting_for_a_slow_non_answering_provider() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Slow), Box::new(Fixed(Some(ctx("aws"))))];
        let start = std::time::Instant::now();
        assert_eq!(detect(providers).await.unwrap().provider, "aws");
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn http_client_builds_in_the_normal_case() {
        assert!(http_client().is_some());
    }

    #[test]
    fn sanitize_trims_and_keeps_normal_values() {
        assert_eq!(sanitize("  i-0abc\n").as_deref(), Some("i-0abc"));
    }

    #[test]
    fn sanitize_rejects_empty_and_control_characters() {
        assert_eq!(sanitize("   "), None);
        assert_eq!(sanitize("a\u{0007}b"), None);
        assert_eq!(
            sanitize("a\nb"),
            None,
            "an embedded newline is a control char"
        );
    }

    #[test]
    fn sanitize_rejects_bidi_and_zero_width_characters() {
        assert_eq!(sanitize("i-0\u{202E}abc"), None);
        assert_eq!(sanitize("i-\u{200B}0abc"), None);
        assert_eq!(sanitize("\u{FEFF}i-0abc"), None);
    }

    #[test]
    fn sanitize_truncates_to_max_field_len() {
        let long = "x".repeat(MAX_FIELD_LEN + 50);
        assert_eq!(sanitize(&long).unwrap().chars().count(), MAX_FIELD_LEN);
    }

    #[tokio::test]
    async fn detect_returns_none_when_no_provider_answers() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Fixed(None)), Box::new(Fixed(None))];
        assert!(detect(providers).await.is_none());
        assert!(detect(vec![]).await.is_none());
    }

    #[tokio::test]
    async fn detect_returns_the_responding_provider() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Fixed(None)), Box::new(Fixed(Some(ctx("gcp"))))];
        assert_eq!(detect(providers).await.unwrap().provider, "gcp");
    }

    #[tokio::test]
    async fn detect_returns_one_of_the_answering_providers() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> = vec![
            Box::new(Fixed(Some(ctx("aws")))),
            Box::new(Fixed(Some(ctx("gcp")))),
        ];
        let got = detect(providers).await.unwrap().provider;
        assert!(got == "aws" || got == "gcp");
    }

    #[tokio::test]
    async fn a_slow_provider_is_cut_off_at_probe_timeout() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Slow), Box::new(Fixed(Some(ctx("azure"))))];
        let started = std::time::Instant::now();
        let got = detect(providers).await;
        assert_eq!(got.unwrap().provider, "azure");
        assert!(
            started.elapsed() < PROBE_TIMEOUT + Duration::from_secs(2),
            "slow provider must not stall detect"
        );
    }
}
