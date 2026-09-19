use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::kubelet::{FetchError, KubeletClient};
use crate::PodCache;

/// One fetch: on success replaces the whole cache and returns `Ok`; on
/// failure keeps the last good cache (stale-while-error) and returns the cause.
pub async fn refresh_once_result(
    client: &KubeletClient,
    cache: &PodCache,
) -> Result<(), FetchError> {
    let map = client.fetch_result().await?;
    cache.replace(map);
    Ok(())
}

/// `refresh_once_result` as a bool (`true` on success).
pub async fn refresh_once(client: &KubeletClient, cache: &PodCache) -> bool {
    refresh_once_result(client, cache).await.is_ok()
}

/// Refreshes `cache` every `interval` until `cancellation` fires (also
/// mid-fetch). Sleeps first: the caller does the initial fetch so it can await
/// it before the pipeline starts consuming events. Logs at warn once when the
/// kubelet goes from healthy to failing, and at info on recovery.
pub fn spawn_refresher(
    client: KubeletClient,
    cache: PodCache,
    interval: Duration,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    spawn_refresher_with_gap(client, cache, interval, MISS_REFRESH_MIN_GAP, cancellation)
}

/// How a fetch outcome changes the refresher's health: it warns once on the
/// healthy -> failing edge and informs once on recovery, never per failure.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HealthTransition {
    StartedFailing,
    StillFailing,
    Recovered,
    StillHealthy,
}

pub(crate) fn health_transition(failing: &mut bool, ok: bool) -> HealthTransition {
    let t = match (*failing, ok) {
        (false, false) => HealthTransition::StartedFailing,
        (true, false) => HealthTransition::StillFailing,
        (true, true) => HealthTransition::Recovered,
        (false, true) => HealthTransition::StillHealthy,
    };
    *failing = !ok;
    t
}

/// Minimum spacing between two fetches when a cache miss asks for an early one.
pub const MISS_REFRESH_MIN_GAP: Duration = Duration::from_secs(10);

/// `spawn_refresher` with an explicit miss-refresh spacing. A lookup miss (a pod
/// that started after the last fetch) wakes the refresher early, but never more
/// often than once per `miss_gap`.
pub fn spawn_refresher_with_gap(
    client: KubeletClient,
    cache: PodCache,
    interval: Duration,
    miss_gap: Duration,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut failing = false;
        let mut last_fetch = tokio::time::Instant::now();
        loop {
            let deadline = last_fetch + interval;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = cache.missed() => {
                    // Fetch early, but not before `miss_gap` since the last fetch,
                    // and never later than the regular interval would have.
                    let target = (last_fetch + miss_gap).min(deadline);
                    tokio::select! {
                        _ = tokio::time::sleep_until(target) => {}
                        _ = cancellation.cancelled() => break,
                    }
                }
                _ = cancellation.cancelled() => break,
            }
            last_fetch = tokio::time::Instant::now();
            let result = tokio::select! {
                r = refresh_once_result(&client, &cache) => r,
                _ = cancellation.cancelled() => break,
            };
            match (health_transition(&mut failing, result.is_ok()), &result) {
                (HealthTransition::Recovered, _) => tracing::info!("kubelet refresh recovered"),
                (HealthTransition::StartedFailing, Err(e)) => {
                    tracing::warn!(error = %e, "kubelet refresh failing; keeping the last good pod cache")
                }
                (HealthTransition::StillFailing, Err(e)) => {
                    tracing::debug!(error = %e, "kubelet refresh still failing")
                }
                _ => {}
            }
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
        assert_eq!(
            cache.lookup("aaa").unwrap().pod_name,
            "pod-a",
            "stale-while-error"
        );
    }

    #[tokio::test]
    async fn cancel_during_a_slow_fetch_returns_promptly() {
        // A listener that accepts but never answers: the fetch hangs until its 5s timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("t");
        std::fs::write(&token, "t").unwrap();
        let cancel = CancellationToken::new();
        let handle = spawn_refresher(
            client_for(&format!("http://{addr}"), &token),
            PodCache::new(),
            Duration::from_millis(10),
            cancel.clone(),
        );
        tokio::time::sleep(Duration::from_millis(200)).await; // fetch now in flight
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("cancel must not wait for the fetch")
            .unwrap();
    }

    #[test]
    fn health_transitions_warn_once_and_recover_once() {
        let mut failing = false;
        assert_eq!(
            health_transition(&mut failing, true),
            HealthTransition::StillHealthy
        );
        assert_eq!(
            health_transition(&mut failing, false),
            HealthTransition::StartedFailing
        );
        assert_eq!(
            health_transition(&mut failing, false),
            HealthTransition::StillFailing
        );
        assert_eq!(
            health_transition(&mut failing, true),
            HealthTransition::Recovered
        );
        assert_eq!(
            health_transition(&mut failing, true),
            HealthTransition::StillHealthy
        );
    }

    #[tokio::test]
    async fn a_cache_miss_triggers_an_early_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("t");
        std::fs::write(&token, "t").unwrap();
        let mock = Mock::new("t", &one_pod("aaa", "pod-a"));
        let base = serve(mock.clone()).await;
        let cache = PodCache::new();
        let cancel = CancellationToken::new();
        // Interval is an hour: only a miss can cause the second fetch.
        let handle = spawn_refresher_with_gap(
            client_for(&base, &token),
            cache.clone(),
            Duration::from_secs(3600),
            Duration::from_millis(30),
            cancel.clone(),
        );
        assert!(cache.lookup("bbb").is_none()); // miss -> early refresh (pod-a only)
        wait_until(|| cache.lookup("aaa").is_some()).await;
        *mock.body.lock().unwrap() = one_pod("bbb", "pod-b");
        assert!(cache.lookup("zzz").is_none()); // another miss
        wait_until(|| cache.lookup("bbb").is_some()).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
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
        let handle = spawn_refresher(
            client_for(&base, &token),
            cache.clone(),
            Duration::from_millis(30),
            cancel.clone(),
        );

        wait_until(|| cache.lookup("aaa").is_some()).await;

        *mock.body.lock().unwrap() = one_pod("bbb", "pod-b");
        wait_until(|| cache.lookup("bbb").is_some()).await;
        assert!(
            cache.lookup("aaa").is_none(),
            "vanished container must drop out"
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("refresher must stop")
            .unwrap();
    }
}
