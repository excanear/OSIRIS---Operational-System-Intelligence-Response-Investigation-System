use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, read_capped, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://169.254.169.254";

/// AWS EC2 Instance Metadata Service, v2 (session-token) only.
pub struct AwsImdsV2 {
    base: String,
    client: Option<reqwest::Client>,
}

impl AwsImdsV2 {
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE)
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            client: http_client(),
        }
    }

    async fn try_probe(&self) -> Result<Option<CloudContext>, reqwest::Error> {
        let Some(client) = &self.client else {
            return Ok(None);
        };
        let resp = client
            .put(format!("{}/latest/api/token", self.base))
            .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
            .send()
            .await?
            .error_for_status()?;
        let Some(token) = read_capped(resp).await? else {
            return Ok(None);
        };
        let resp = client
            .get(format!(
                "{}/latest/dynamic/instance-identity/document",
                self.base
            ))
            .header("X-aws-ec2-metadata-token", token.trim())
            .send()
            .await?
            .error_for_status()?;
        let Some(body) = read_capped(resp).await? else {
            return Ok(None);
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
            tracing::debug!("aws imds returned malformed json");
            return Ok(None);
        };
        let field = |k: &str| doc.get(k).and_then(|v| v.as_str()).and_then(sanitize);
        let (instance_id, region) = (field("instanceId"), field("region"));
        if instance_id.is_none() && region.is_none() {
            tracing::debug!("aws imds response has no usable fields");
            return Ok(None);
        }
        Ok(Some(CloudContext {
            provider: "aws".to_string(),
            instance_id,
            region,
        }))
    }
}

impl Default for AwsImdsV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudMetadataProvider for AwsImdsV2 {
    /// The two-step flow's 1s budget is enforced by `detect()`'s outer
    /// `PROBE_TIMEOUT` wrapper; calling `probe()` directly can take up to 2x.
    async fn probe(&self) -> Option<CloudContext> {
        match self.try_probe().await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::debug!(error = %e, "aws imds probe failed");
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
    use axum::routing::{get, put};
    use axum::Router;

    async fn token(headers: HeaderMap) -> impl IntoResponse {
        if headers.contains_key("x-aws-ec2-metadata-token-ttl-seconds") {
            (StatusCode::OK, "tok-123").into_response()
        } else {
            StatusCode::BAD_REQUEST.into_response()
        }
    }

    async fn doc(headers: HeaderMap) -> impl IntoResponse {
        let ok = headers
            .get("x-aws-ec2-metadata-token")
            .and_then(|v| v.to_str().ok())
            == Some("tok-123");
        if ok {
            (
                StatusCode::OK,
                r#"{"instanceId":"i-0abc","region":"us-east-1"}"#,
            )
                .into_response()
        } else {
            StatusCode::UNAUTHORIZED.into_response()
        }
    }

    fn happy() -> Router {
        Router::new()
            .route("/latest/api/token", put(token))
            .route("/latest/dynamic/instance-identity/document", get(doc))
    }

    #[tokio::test]
    async fn probes_a_v2_metadata_service() {
        let base = serve(happy()).await;
        let got = AwsImdsV2::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.provider, "aws");
        assert_eq!(got.instance_id.as_deref(), Some("i-0abc"));
        assert_eq!(got.region.as_deref(), Some("us-east-1"));
    }

    #[tokio::test]
    async fn token_step_failing_yields_none() {
        let router =
            Router::new().route("/latest/api/token", put(|| async { StatusCode::FORBIDDEN }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn document_404_yields_none() {
        let router = Router::new().route("/latest/api/token", put(|| async { "tok-123" }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn malformed_json_yields_none() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { "not json" }),
            );
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn control_char_field_is_dropped_but_other_field_survives() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { r#"{"instanceId":"i-\u0007bad","region":"eu-west-1"}"# }),
            );
        let base = serve(router).await;
        let got = AwsImdsV2::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.instance_id, None);
        assert_eq!(got.region.as_deref(), Some("eu-west-1"));
    }

    #[tokio::test]
    async fn no_usable_field_yields_none() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { "{}" }),
            );
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn oversized_document_yields_none() {
        let big = format!(
            r#"{{"instanceId":"i-1","pad":"{}"}}"#,
            "x".repeat(crate::MAX_BODY_LEN)
        );
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(move || {
                    let big = big.clone();
                    async move { big }
                }),
            );
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn oversized_token_yields_none() {
        let big = "t".repeat(crate::MAX_BODY_LEN + 1);
        let router = Router::new()
            .route(
                "/latest/api/token",
                put(move || {
                    let big = big.clone();
                    async move { big }
                }),
            )
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { r#"{"instanceId":"i-1"}"# }),
            );
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn missing_client_yields_none() {
        let p = AwsImdsV2 {
            base: "http://127.0.0.1:1".into(),
            client: None,
        };
        assert!(p.probe().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        // Port 1 on loopback: connection refused.
        assert!(AwsImdsV2::with_base_url("http://127.0.0.1:1")
            .probe()
            .await
            .is_none());
    }
}
