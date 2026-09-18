use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::kubelet::KubeletClient;
use crate::PodCache;

/// One fetch: on success replaces the whole cache and returns `true`; on
/// failure keeps the last good cache (stale-while-error) and returns `false`.
pub async fn refresh_once(client: &KubeletClient, cache: &PodCache) -> bool {
    match client.fetch().await {
        Some(map) => {
            cache.replace(map);
            true
        }
        None => {
            tracing::debug!("kubelet refresh failed; keeping the last good pod cache");
            false
        }
    }
}

/// Refreshes `cache` every `interval` until `cancellation` fires. Sleeps
/// first: the caller does the initial fetch with `refresh_once` so it can
/// await it before the pipeline starts consuming events.
pub fn spawn_refresher(
    client: KubeletClient,
    cache: PodCache,
    interval: Duration,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancellation.cancelled() => break,
            }
            refresh_once(&client, &cache).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::kubelet::tests::{client_for, serve, Mock};
    use crate::PodCache;

    fn one_pod(container: &str, name: &str) -> String {
        format!(
            r#"{{"items":[{{"metadata":{{"name":"{name}","namespace":"ns"}},"status":{{"containerStatuses":[{{"containerID":"containerd://{container}"}}]}}}}]}}"#
        )
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..100 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("condition not reached in time");
    }

    #[tokio::test]
    async fn refresh_once_replaces_the_cache_on_success_and_reports_true() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("t");
        std::fs::write(&token, "t").unwrap();
        let base = serve(Mock::new("t", &one_pod("aaa", "pod-a"))).await;
        let client = client_for(&base, &token);
        let cache = PodCache::new();
        assert!(refresh_once(&client, &cache).await);
        assert_eq!(cache.lookup("aaa").unwrap().pod_name, "pod-a");
    }

    #[tokio::test]
    async fn refresh_once_failure_keeps_the_last_good_cache_and_reports_false() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("t");
        std::fs::write(&token, "t").unwrap();
        let mock = Mock::new("t", &one_pod("aaa", "pod-a"));
        let base = serve(mock.clone()).await;
        let client = client_for(&base, &token);
        let cache = PodCache::new();
        assert!(refresh_once(&client, &cache).await);

        *mock.status.lock().unwrap() = 500;
        assert!(!refresh_once(&client, &cache).await);
        assert_eq!(cache.lookup("aaa").unwrap().pod_name, "pod-a", "stale-while-error");
    }

    #[tokio::test]
    async fn the_refresher_picks_up_changes_drops_vanished_containers_and_stops_on_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("t");
        std::fs::write(&token, "t").unwrap();
        let mock = Mock::new("t", &one_pod("aaa", "pod-a"));
        let base = serve(mock.clone()).await;
        let cache = PodCache::new();
        let cancel = CancellationToken::new();
        let handle = spawn_refresher(client_for(&base, &token), cache.clone(), Duration::from_millis(30), cancel.clone());

        wait_until(|| cache.lookup("aaa").is_some()).await;

        *mock.body.lock().unwrap() = one_pod("bbb", "pod-b");
        wait_until(|| cache.lookup("bbb").is_some()).await;
        assert!(cache.lookup("aaa").is_none(), "vanished container must drop out");

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle).await.expect("refresher must stop").unwrap();
    }
}
