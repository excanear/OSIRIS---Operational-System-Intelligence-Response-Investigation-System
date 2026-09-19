use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, read_capped, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://169.254.169.254";

/// Azure Instance Metadata Service.
pub struct AzureImds {
    base: String,
    client: Option<reqwest::Client>,
}

impl AzureImds {
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
            .get(format!(
                "{}/metadata/instance?api-version=2021-02-01",
                self.base
            ))
            .header("Metadata", "true")
            .send()
            .await?
            .error_for_status()?;
        let Some(body) = read_capped(resp).await? else {
            return Ok(None);
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
            tracing::debug!("azure imds returned malformed json");
            return Ok(None);
        };
        let Some(compute) = doc.get("compute") else {
            tracing::debug!("azure imds response has no compute object");
            return Ok(None);
        };
        let field = |k: &str| compute.get(k).and_then(|v| v.as_str()).and_then(sanitize);
        let (instance_id, region) = (field("vmId"), field("location"));
        if instance_id.is_none() && region.is_none() {
            tracing::debug!("azure imds response has no usable fields");
            return Ok(None);
        }
        Ok(Some(CloudContext {
            provider: "azure".to_string(),
            instance_id,
            region,
        }))
    }
}

impl Default for AzureImds {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudMetadataProvider for AzureImds {
    async fn probe(&self) -> Option<CloudContext> {
        match self.try_probe().await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::debug!(error = %e, "azure imds probe failed");
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

    async fn instance(headers: HeaderMap) -> impl IntoResponse {
        if headers.get("metadata").and_then(|v| v.to_str().ok()) == Some("true") {
            (
                StatusCode::OK,
                r#"{"compute":{"vmId":"vm-42","location":"westeurope"}}"#,
            )
                .into_response()
        } else {
            StatusCode::BAD_REQUEST.into_response()
        }
    }

    #[tokio::test]
    async fn probes_azure_imds_sending_the_required_header() {
        let base = serve(Router::new().route("/metadata/instance", get(instance))).await;
        let got = AzureImds::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.provider, "azure");
        assert_eq!(got.instance_id.as_deref(), Some("vm-42"));
        assert_eq!(got.region.as_deref(), Some("westeurope"));
    }

    #[tokio::test]
    async fn not_found_yields_none() {
        let base = serve(Router::new()).await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn malformed_json_yields_none() {
        let base =
            serve(Router::new().route("/metadata/instance", get(|| async { "<html>" }))).await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn missing_compute_object_yields_none() {
        let base =
            serve(Router::new().route("/metadata/instance", get(|| async { r#"{"network":{}}"# })))
                .await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn oversized_body_yields_none() {
        let big = format!(
            r#"{{"compute":{{"vmId":"v","pad":"{}"}}}}"#,
            "x".repeat(crate::MAX_BODY_LEN)
        );
        let router = Router::new().route(
            "/metadata/instance",
            get(move || {
                let big = big.clone();
                async move { big }
            }),
        );
        let base = serve(router).await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn missing_client_yields_none() {
        let p = AzureImds {
            base: "http://127.0.0.1:1".into(),
            client: None,
        };
        assert!(p.probe().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        assert!(AzureImds::with_base_url("http://127.0.0.1:1")
            .probe()
            .await
            .is_none());
    }
}
