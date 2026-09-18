use std::path::{Path, PathBuf};
use std::time::Duration;

use osiris_k8s_context::{refresh_once, spawn_refresher, KubeletClient, KubeletConfig, PodCache};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::K8sContextConfig;

pub const DEFAULT_SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const DEFAULT_KUBELET_URL: &str = "https://127.0.0.1:10250";

fn token_path(cfg: &K8sContextConfig) -> &str {
    cfg.token_path.as_deref().unwrap_or(DEFAULT_SA_TOKEN_PATH)
}

/// Kubernetes detection gate (evaluated once at startup): enabled AND (a
/// kubelet URL was configured OR the service-account token file exists).
/// Off a Kubernetes node nothing connects to `127.0.0.1:10250`.
pub fn k8s_context_active(cfg: &K8sContextConfig) -> bool {
    cfg.enabled && (cfg.kubelet_url.is_some() || Path::new(token_path(cfg)).exists())
}

/// When active: builds the kubelet client, AWAITS one initial fetch (so the
/// cache is warm before the pipeline consumes events; a failed fetch just
/// leaves it empty), and spawns the periodic refresher. `None` when inactive
/// or the client cannot be built — the agent then runs exactly as before 8e.
pub async fn start_pod_cache(
    cfg: &K8sContextConfig,
    cancellation: &CancellationToken,
) -> Option<(PodCache, JoinHandle<()>)> {
    if !k8s_context_active(cfg) {
        return None;
    }
    let client = KubeletClient::new(KubeletConfig {
        url: cfg.kubelet_url.clone().unwrap_or_else(|| DEFAULT_KUBELET_URL.to_string()),
        token_path: PathBuf::from(token_path(cfg)),
        ca_path: cfg.ca_path.as_ref().map(PathBuf::from),
        insecure_skip_verify: cfg.insecure_skip_verify,
    });
    let Some(client) = client else {
        tracing::warn!("kubernetes context is configured but the kubelet client could not be built; continuing without pod context");
        return None;
    };
    let cache = PodCache::new();
    if refresh_once(&client, &cache).await {
        tracing::info!(pods = cache.len(), "kubernetes pod context loaded");
    } else {
        tracing::warn!("initial kubelet fetch failed; pod context will fill in when the kubelet becomes reachable");
    }
    let interval = Duration::from_secs(cfg.refresh_secs.max(1));
    let handle = spawn_refresher(client, cache.clone(), interval, cancellation.clone());
    Some((cache, handle))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    use super::*;

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn token(dir: &tempfile::TempDir) -> String {
        let path = dir.path().join("token");
        std::fs::write(&path, "tok").unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn disabled_is_never_active() {
        let cfg = K8sContextConfig { enabled: false, kubelet_url: Some("https://x".into()), ..Default::default() };
        assert!(!k8s_context_active(&cfg));
    }

    #[test]
    fn no_url_and_no_token_file_is_inactive() {
        let cfg = K8sContextConfig { token_path: Some("/no/such/token".into()), ..Default::default() };
        assert!(!k8s_context_active(&cfg));
    }

    #[test]
    fn an_explicit_kubelet_url_activates_even_without_a_token_file() {
        let cfg = K8sContextConfig {
            kubelet_url: Some("https://10.0.0.1:10250".into()),
            token_path: Some("/no/such/token".into()),
            ..Default::default()
        };
        assert!(k8s_context_active(&cfg));
    }

    #[test]
    fn an_existing_token_file_activates() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = K8sContextConfig { token_path: Some(token(&dir)), ..Default::default() };
        assert!(k8s_context_active(&cfg));
    }

    #[tokio::test]
    async fn inactive_config_starts_nothing() {
        let cfg = K8sContextConfig { enabled: false, ..Default::default() };
        let cancel = CancellationToken::new();
        assert!(start_pod_cache(&cfg, &cancel).await.is_none());
    }

    #[tokio::test]
    async fn start_pod_cache_does_an_awaited_initial_fetch_before_returning() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"{"items":[{"metadata":{"name":"web-0","namespace":"prod"},"status":{"containerStatuses":[{"containerID":"containerd://abc"}]}}]}"#;
        let router = Router::new().route(
            "/pods",
            get(move |headers: HeaderMap| async move {
                if headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok") {
                    (axum::http::StatusCode::OK, body).into_response()
                } else {
                    axum::http::StatusCode::UNAUTHORIZED.into_response()
                }
            }),
        );
        let base = serve(router).await;
        let cfg = K8sContextConfig {
            kubelet_url: Some(base),
            token_path: Some(token(&dir)),
            refresh_secs: 3600,
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let (cache, handle) = start_pod_cache(&cfg, &cancel).await.expect("active");
        assert_eq!(cache.lookup("abc").unwrap().pod_name, "web-0", "initial fetch must already be applied");
        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn an_unreachable_kubelet_still_returns_an_empty_cache_and_a_running_refresher() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = K8sContextConfig {
            kubelet_url: Some("http://127.0.0.1:1".into()),
            token_path: Some(token(&dir)),
            refresh_secs: 3600,
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let (cache, handle) = start_pod_cache(&cfg, &cancel).await.expect("active");
        assert!(cache.is_empty());
        cancel.cancel();
        handle.await.unwrap();
    }
}
