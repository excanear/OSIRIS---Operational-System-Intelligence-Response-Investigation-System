use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Minimal in-process metrics registry (per-lane bus counters, sensor
/// event counts — ARCHITECTURE.md §8.2/§23). Kept dependency-free rather
/// than pulling in a full metrics facade for Phase 0's needs.
#[derive(Default)]
pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, Counter>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counter(&self, name: &str) -> Counter {
        if let Some(c) = self.counters.read().unwrap().get(name) {
            return c.clone();
        }
        let mut counters = self.counters.write().unwrap();
        counters.entry(name.to_string()).or_default().clone()
    }

    pub fn snapshot(&self) -> HashMap<String, u64> {
        self.counters
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.get()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_are_visible_via_snapshot() {
        let registry = MetricsRegistry::new();
        registry.counter("bus.high.enqueued").increment();
        registry.counter("bus.high.enqueued").add(4);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.get("bus.high.enqueued"), Some(&5));
    }

    #[test]
    fn same_name_returns_the_same_shared_counter() {
        let registry = MetricsRegistry::new();
        let a = registry.counter("sensor.exec.events");
        let b = registry.counter("sensor.exec.events");
        a.increment();
        assert_eq!(b.get(), 1);
    }
}
