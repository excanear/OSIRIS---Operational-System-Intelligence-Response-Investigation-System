use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://metadata.google.internal";

/// GCP Compute Engine metadata server.
pub struct GcpMetadata {
    base: String,
    client: reqwest::Client,
}

/// `projects/<n>/zones/us-central1-a` (or a bare zone) -> `us-central1`.
pub(crate) fn gcp_region_from_zone(zone: &str) -> Option<String> {
    let segment = zone.trim().rsplit('/').next().unwrap_or("");
    if segment.is_empty() {
        return None;
    }
    Some(segment.rsplit_once('-').map(|(region, _)| region).unwrap_or(segment).to_string())
}

impl GcpMetadata {
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE)
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        Self { base: base.into().trim_end_matches('/').to_string(), client: http_client() }
    }

    async fn get_text(&self, path: &str) -> Result<String, reqwest::Error> {
        self.client
            .get(format!("{}/computeMetadata/v1/instance/{path}", self.base))
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }

    async fn try_probe(&self) -> Result<Option<CloudContext>, reqwest::Error> {
        let instance_id = sanitize(&self.get_text("id").await?);
        // A zone failure must not discard an otherwise-valid instance id.
        let region = match self.get_text("zone").await {
            Ok(zone) => gcp_region_from_zone(&zone).as_deref().and_then(sanitize),
            Err(e) => {
                tracing::debug!(error = %e, "gcp zone lookup failed");
                None
            }
        };
        if instance_id.is_none() && region.is_none() {
            tracing::debug!("gcp metadata response has no usable fields");
            return Ok(None);
        }
        Ok(Some(CloudContext { provider: "gcp".to_string(), instance_id, region }))
    }
}

impl Default for GcpMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudMetadataProvider for GcpMetadata {
    async fn probe(&self) -> Option<CloudContext> {
        match self.try_probe().await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::debug!(error = %e, "gcp metadata probe failed");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::serve;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    fn flavored(headers: &HeaderMap) -> bool {
        headers.get("metadata-flavor").and_then(|v| v.to_str().ok()) == Some("Google")
    }

    async fn id(headers: HeaderMap) -> impl IntoResponse {
        if flavored(&headers) { (StatusCode::OK, "1234567890\n").into_response() } else { StatusCode::FORBIDDEN.into_response() }
    }

    async fn zone(headers: HeaderMap) -> impl IntoResponse {
        if flavored(&headers) {
            (StatusCode::OK, "projects/123/zones/us-central1-a").into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        }
    }

    #[test]
    fn zone_maps_to_region() {
        assert_eq!(gcp_region_from_zone("projects/123/zones/us-central1-a").as_deref(), Some("us-central1"));
        assert_eq!(gcp_region_from_zone("europe-west4-b").as_deref(), Some("europe-west4"));
        assert_eq!(gcp_region_from_zone("weird").as_deref(), Some("weird"));
        assert_eq!(gcp_region_from_zone(""), None);
    }

    #[tokio::test]
    async fn probes_gcp_metadata_sending_the_required_header() {
        let router = Router::new()
            .route("/computeMetadata/v1/instance/id", get(id))
            .route("/computeMetadata/v1/instance/zone", get(zone));
        let base = serve(router).await;
        let got = GcpMetadata::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.provider, "gcp");
        assert_eq!(got.instance_id.as_deref(), Some("1234567890"), "trailing newline trimmed");
        assert_eq!(got.region.as_deref(), Some("us-central1"));
    }

    #[tokio::test]
    async fn id_endpoint_missing_yields_none() {
        let base = serve(Router::new()).await;
        assert!(GcpMetadata::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn zone_failure_still_returns_the_instance_id() {
        let router = Router::new().route("/computeMetadata/v1/instance/id", get(id));
        let base = serve(router).await;
        let got = GcpMetadata::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.instance_id.as_deref(), Some("1234567890"));
        assert_eq!(got.region, None);
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        assert!(GcpMetadata::with_base_url("http://127.0.0.1:1").probe().await.is_none());
    }
}
