use std::time::Duration;

use osiris_cloud_context::{detect, AwsImdsV2, AzureImds, CloudMetadataProvider, GcpMetadata};
use osiris_schema::CloudContext;

use crate::config::CloudMetadataConfig;

/// Outer bound on the whole startup probe so boot is never blocked longer.
pub const DETECT_TIMEOUT: Duration = Duration::from_secs(2);

/// An override is used only if it is a sane http(s) URL; an invalid one is
/// logged and that provider is left out (never silently redirected).
fn override_ok(name: &str, url: &Option<String>) -> bool {
    match url {
        Some(u) if !osiris_cloud_context::valid_base_url(u) => {
            tracing::warn!(provider = name, "ignoring invalid cloud_metadata base_url override; provider disabled");
            false
        }
        _ => true,
    }
}

pub fn build_providers(cfg: &CloudMetadataConfig) -> Vec<Box<dyn CloudMetadataProvider>> {
    if !cfg.enabled {
        return vec![];
    }
    let aws = match &cfg.aws_base_url {
        Some(url) => AwsImdsV2::with_base_url(url.clone()),
        None => AwsImdsV2::new(),
    };
    let azure = match &cfg.azure_base_url {
        Some(url) => AzureImds::with_base_url(url.clone()),
        None => AzureImds::new(),
    };
    let gcp = match &cfg.gcp_base_url {
        Some(url) => GcpMetadata::with_base_url(url.clone()),
        None => GcpMetadata::new(),
    };
    let mut providers: Vec<Box<dyn CloudMetadataProvider>> = Vec::new();
    if override_ok("aws", &cfg.aws_base_url) {
        providers.push(Box::new(aws));
    }
    if override_ok("azure", &cfg.azure_base_url) {
        providers.push(Box::new(azure));
    }
    if override_ok("gcp", &cfg.gcp_base_url) {
        providers.push(Box::new(gcp));
    }
    providers
}

/// `None` when disabled, on-prem/bare-metal, or the probe times out —
/// never a startup failure.
pub async fn detect_cloud_context(cfg: &CloudMetadataConfig) -> Option<CloudContext> {
    let providers = build_providers(cfg);
    if providers.is_empty() {
        return None;
    }
    tokio::time::timeout(DETECT_TIMEOUT, detect(providers))
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, put};
    use axum::Router;

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn none_reachable() -> CloudMetadataConfig {
        CloudMetadataConfig {
            enabled: true,
            aws_base_url: Some("http://127.0.0.1:1".into()),
            azure_base_url: Some("http://127.0.0.1:1".into()),
            gcp_base_url: Some("http://127.0.0.1:1".into()),
        }
    }

    #[test]
    fn disabled_builds_no_providers() {
        let cfg = CloudMetadataConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(build_providers(&cfg).is_empty());
    }

    #[test]
    fn enabled_builds_three_providers() {
        assert_eq!(build_providers(&CloudMetadataConfig::default()).len(), 3);
    }

    #[tokio::test]
    async fn disabled_skips_probing_entirely() {
        let cfg = CloudMetadataConfig {
            enabled: false,
            ..none_reachable()
        };
        assert!(detect_cloud_context(&cfg).await.is_none());
    }

    #[tokio::test]
    async fn nothing_reachable_yields_none_without_error() {
        assert!(detect_cloud_context(&none_reachable()).await.is_none());
    }

    #[tokio::test]
    async fn base_url_override_is_wired_to_the_provider() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { r#"{"instanceId":"i-9","region":"ap-south-1"}"# }),
            );
        let base = serve(router).await;
        let cfg = CloudMetadataConfig {
            aws_base_url: Some(base),
            ..none_reachable()
        };
        let got = detect_cloud_context(&cfg).await.unwrap();
        assert_eq!(got.provider, "aws");
        assert_eq!(got.instance_id.as_deref(), Some("i-9"));
    }
}

#[cfg(test)]
mod override_tests {
    use super::*;

    #[test]
    fn an_invalid_base_url_override_disables_only_that_provider() {
        let cfg = CloudMetadataConfig {
            enabled: true,
            aws_base_url: Some("file:///etc/passwd".into()),
            azure_base_url: None,
            gcp_base_url: Some("http://127.0.0.1:1".into()),
        };
        assert_eq!(build_providers(&cfg).len(), 2);
    }
}
