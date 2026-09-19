use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use osiris_pipeline::PodLookup;
use osiris_schema::PodRef;

/// Upper bound on cached containers. A node runs far fewer; the cap only
/// exists so a hostile or buggy kubelet response cannot grow memory.
pub const MAX_CACHE_ENTRIES: usize = 10_000;

/// Cheap-to-clone handle over the container-id -> pod map the refresher
/// keeps fresh and the pipeline reads (synchronously) on every event.
#[derive(Clone, Default)]
pub struct PodCache {
    inner: Arc<RwLock<HashMap<String, PodRef>>>,
}

impl PodCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole map (so containers that vanished drop out).
    /// Beyond `MAX_CACHE_ENTRIES`, the surplus (arbitrary) entries are dropped.
    pub fn replace(&self, map: HashMap<String, PodRef>) {
        let map = if map.len() > MAX_CACHE_ENTRIES {
            map.into_iter().take(MAX_CACHE_ENTRIES).collect()
        } else {
            map
        };
        *self.inner.write().unwrap_or_else(|p| p.into_inner()) = map;
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, container_id: &str) -> Option<PodRef> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(container_id)
            .cloned()
    }
}

impl PodLookup for PodCache {
    fn pod_for(&self, container_id: &str) -> Option<PodRef> {
        self.lookup(container_id)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use osiris_pipeline::PodLookup;
    use osiris_schema::PodRef;

    use super::*;

    fn pod(name: &str) -> PodRef {
        PodRef {
            pod_name: name.to_string(),
            namespace: "ns".to_string(),
        }
    }

    #[test]
    fn empty_cache_resolves_nothing() {
        let cache = PodCache::new();
        assert!(cache.is_empty());
        assert!(cache.lookup("x").is_none());
    }

    #[test]
    fn replace_swaps_the_whole_map_so_vanished_containers_drop_out() {
        let cache = PodCache::new();
        cache.replace(HashMap::from([("a".to_string(), pod("a-pod"))]));
        assert_eq!(cache.lookup("a").unwrap().pod_name, "a-pod");
        cache.replace(HashMap::from([("b".to_string(), pod("b-pod"))]));
        assert!(cache.lookup("a").is_none(), "old container must be gone");
        assert_eq!(cache.lookup("b").unwrap().pod_name, "b-pod");
    }

    #[test]
    fn clones_share_state() {
        let cache = PodCache::new();
        let other = cache.clone();
        cache.replace(HashMap::from([("a".to_string(), pod("a-pod"))]));
        assert_eq!(other.len(), 1);
    }

    #[test]
    fn replace_enforces_the_entry_cap() {
        let cache = PodCache::new();
        let big: HashMap<String, PodRef> = (0..MAX_CACHE_ENTRIES + 500)
            .map(|i| (format!("id-{i}"), pod("p")))
            .collect();
        cache.replace(big);
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
    }

    #[test]
    fn implements_pod_lookup() {
        let cache = PodCache::new();
        cache.replace(HashMap::from([("a".to_string(), pod("a-pod"))]));
        let lookup: &dyn PodLookup = &cache;
        assert_eq!(lookup.pod_for("a").unwrap().pod_name, "a-pod");
    }
}
