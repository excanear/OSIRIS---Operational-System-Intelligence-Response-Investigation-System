//! Sandboxed plugin execution with per-event budgets (spec §5.2–§5.6, §5.8).
//!
//! Each `*_batch` call gives every plugin one fresh `Store` + instance, reused
//! for that batch and dropped at its end; after any failure the instance is
//! discarded and the next event gets a fresh one. Fuel is reset to
//! `fuel_per_event` before every event. Failure messages and log lines carry
//! only the plugin name, the failure kind and a fixed description — never
//! event or output content.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use osiris_schema::{Alert, CanonicalEvent};
use serde::Serialize;
use wasmtime::{Engine, Memory, Store, Trap, TypedFunc};

use crate::abi::{parse_output, PluginOutput, MAX_OUTPUT_BYTES};
use crate::config::{validate_plugins, ConfigError, PluginConfig, PluginKind};
use crate::load::{load_plugin, new_engine, new_store, HostState, LoadedPlugin};

/// At most one failure warning per plugin per this many seconds.
const WARN_EVERY_SECS: u64 = 60;

/// Status and counters of one configured plugin (spec §5.8).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PluginStatus {
    pub name: String,
    pub kind: PluginKind,
    pub enabled: bool,
    pub sha256: String,
    pub calls: u64,
    pub alerts: u64,
    pub tags: u64,
    pub failures_trap: u64,
    pub failures_fuel: u64,
    pub failures_memory: u64,
    pub failures_output: u64,
    pub last_failure: Option<String>,
    pub last_failure_at: Option<u64>,
    pub total_fuel_used: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Trap,
    Fuel,
    Memory,
    Output,
}

impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            FailureKind::Trap => "trap",
            FailureKind::Fuel => "fuel",
            FailureKind::Memory => "memory",
            FailureKind::Output => "output",
        }
    }
}

/// One failed call. `detail` is a fixed description (or a wasmtime trap
/// code's text), never event or output content.
#[derive(Debug)]
struct Failure {
    kind: FailureKind,
    detail: String,
}

impl Failure {
    fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// A bad pointer/length or invalid output; a memory failure instead when
    /// the limiter denied a memory growth during the call.
    fn output(memory_denied: bool, detail: impl Into<String>) -> Self {
        if memory_denied {
            Self::new(FailureKind::Memory, "memory limit reached")
        } else {
            Self::new(FailureKind::Output, detail)
        }
    }

    /// Classifies an error raised by guest code.
    fn from_wasm(err: &wasmtime::Error, memory_denied: bool) -> Self {
        match err.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => Self::new(FailureKind::Fuel, "fuel exhausted"),
            _ if memory_denied => Self::new(FailureKind::Memory, "memory limit reached"),
            Some(trap) => Self::new(FailureKind::Trap, trap.to_string()),
            None => Self::new(FailureKind::Trap, "guest call failed"),
        }
    }
}

#[derive(Default)]
struct Counters {
    calls: AtomicU64,
    alerts: AtomicU64,
    tags: AtomicU64,
    failures_trap: AtomicU64,
    failures_fuel: AtomicU64,
    failures_memory: AtomicU64,
    failures_output: AtomicU64,
    total_fuel_used: AtomicU64,
    /// Unix seconds of the last warning, 0 = never.
    last_warn_secs: AtomicU64,
    /// (message, unix nanoseconds).
    last_failure: Mutex<Option<(String, u64)>>,
}

fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Relaxed);
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Claims the plugin's warning slot if the last warning is at least
/// `WARN_EVERY_SECS` old (or there was none). One winner per window, even
/// under concurrent batches.
fn should_warn(last_warn_secs: &AtomicU64, now_secs: u64) -> bool {
    let now_secs = now_secs.max(1); // 0 means "never warned"
    let last = last_warn_secs.load(Relaxed);
    if last != 0 && now_secs < last.saturating_add(WARN_EVERY_SECS) {
        return false;
    }
    last_warn_secs
        .compare_exchange(last, now_secs, Relaxed, Relaxed)
        .is_ok()
}

struct Plugin {
    config: PluginConfig,
    /// `None` when disabled.
    loaded: Option<LoadedPlugin>,
    counters: Counters,
}

impl Plugin {
    fn record_failure(&self, f: Failure) {
        let c = &self.counters;
        let counter = match f.kind {
            FailureKind::Trap => &c.failures_trap,
            FailureKind::Fuel => &c.failures_fuel,
            FailureKind::Memory => &c.failures_memory,
            FailureKind::Output => &c.failures_output,
        };
        add(counter, 1);
        let now = now_ns();
        *c.last_failure.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((format!("{}: {}", f.kind.as_str(), f.detail), now));

        if should_warn(&c.last_warn_secs, now / 1_000_000_000) {
            tracing::warn!(
                plugin = %self.config.name,
                failure = f.kind.as_str(),
                detail = %f.detail,
                "plugin call failed; the event continues without its output"
            );
        }
    }
}

/// One live instance of a plugin, valid for the rest of a batch.
struct Live {
    store: Store<HostState>,
    alloc: TypedFunc<i32, i32>,
    on_event: TypedFunc<(i32, i32), i64>,
    memory: Memory,
}

impl Live {
    fn new(engine: &Engine, p: &LoadedPlugin) -> Result<Live, Failure> {
        let mut store = new_store(engine, &p.config);
        store
            .set_fuel(p.config.fuel_per_event)
            .map_err(|_| Failure::new(FailureKind::Trap, "cannot set fuel"))?;
        let instance = match p.pre.instantiate(&mut store) {
            Ok(i) => i,
            Err(e) => return Err(Failure::from_wasm(&e, store.data().limits.memory_denied)),
        };
        let missing = |_| Failure::new(FailureKind::Trap, "instance lacks an ABI export");
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "osiris_alloc")
            .map_err(missing)?;
        let on_event = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "osiris_on_event")
            .map_err(missing)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| Failure::new(FailureKind::Trap, "instance lacks an ABI export"))?;
        Ok(Live {
            store,
            alloc,
            on_event,
            memory,
        })
    }

    fn memory_denied(&self) -> bool {
        self.store.data().limits.memory_denied
    }

    /// One `osiris_alloc` + `osiris_on_event` call under a fresh fuel budget.
    /// Returns the outcome and the fuel consumed.
    fn call(&mut self, fuel: u64, input: &[u8]) -> (Result<Option<Vec<u8>>, Failure>, u64) {
        self.store.data_mut().limits.memory_denied = false;
        if self.store.set_fuel(fuel).is_err() {
            return (Err(Failure::new(FailureKind::Trap, "cannot set fuel")), 0);
        }
        let result = self.invoke(input);
        let used = fuel.saturating_sub(self.store.get_fuel().unwrap_or(0));
        (result, used)
    }

    fn invoke(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>, Failure> {
        let len = i32::try_from(input.len())
            .map_err(|_| Failure::new(FailureKind::Output, "event too large for the ABI"))?;
        let ptr = match self.alloc.call(&mut self.store, len) {
            Ok(p) => p,
            Err(e) => return Err(Failure::from_wasm(&e, self.memory_denied())),
        };
        if self
            .memory
            .write(&mut self.store, ptr as u32 as usize, input)
            .is_err()
        {
            return Err(Failure::output(
                self.memory_denied(),
                "osiris_alloc returned a pointer outside memory",
            ));
        }
        let ret = match self.on_event.call(&mut self.store, (ptr, len)) {
            Ok(r) => r as u64,
            Err(e) => return Err(Failure::from_wasm(&e, self.memory_denied())),
        };
        if ret == 0 {
            return Ok(None);
        }
        let (out_ptr, out_len) = (ret >> 32, ret & 0xFFFF_FFFF);
        if out_len > MAX_OUTPUT_BYTES as u64 {
            return Err(Failure::output(
                self.memory_denied(),
                "output exceeds 64 KiB",
            ));
        }
        // Both halves are < 2^32, so the u64 sum cannot overflow.
        let end = out_ptr + out_len;
        let data = self.memory.data(&self.store);
        match usize::try_from(out_ptr)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(s, e)| data.get(s..e))
        {
            Some(bytes) => Ok(Some(bytes.to_vec())),
            None => Err(Failure::output(
                self.memory_denied(),
                "output range lies outside memory",
            )),
        }
    }
}

/// The event as plugins see it: `serde_json::to_value(event)` minus `raw_event`.
fn event_input(event: &CanonicalEvent) -> Option<Vec<u8>> {
    let mut value = serde_json::to_value(event).ok()?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("raw_event");
    }
    serde_json::to_vec(&value).ok()
}

/// The configured plugins, ready to run. `Send + Sync`; calls are synchronous.
pub struct PluginSet {
    /// Created only when at least one plugin is enabled.
    engine: Option<Engine>,
    plugins: Vec<Plugin>,
}

impl PluginSet {
    /// Validates the configuration and loads every enabled plugin, in order.
    /// Disabled plugins are not read or run but are listed in `status`.
    pub fn load(cfgs: &[PluginConfig]) -> Result<PluginSet, ConfigError> {
        validate_plugins(cfgs)?;
        let engine = cfgs.iter().any(|c| c.enabled).then(new_engine);
        let mut plugins = Vec::with_capacity(cfgs.len());
        for cfg in cfgs {
            let loaded = match (&engine, cfg.enabled) {
                (Some(engine), true) => Some(load_plugin(engine, cfg)?),
                _ => None,
            };
            plugins.push(Plugin {
                config: cfg.clone(),
                loaded,
                counters: Counters::default(),
            });
        }
        Ok(PluginSet { engine, plugins })
    }

    /// True when no plugin will run (none configured, or all disabled).
    pub fn is_empty(&self) -> bool {
        self.plugins.iter().all(|p| p.loaded.is_none())
    }

    fn runnable(&self, kind: PluginKind) -> impl Iterator<Item = (&Plugin, &LoadedPlugin)> {
        self.plugins
            .iter()
            .filter(move |p| p.config.kind == kind)
            .filter_map(|p| p.loaded.as_ref().map(|l| (p, l)))
    }

    /// Runs one plugin over a batch with one instance, replaced after any
    /// failure. `accept` applies a valid output for event `i`; an error from
    /// it counts as a failure and nothing of that output may have been applied.
    fn run_plugin(
        &self,
        plugin: &Plugin,
        loaded: &LoadedPlugin,
        inputs: &[Option<Vec<u8>>],
        mut accept: impl FnMut(usize, PluginOutput) -> Result<(), Failure>,
    ) {
        let Some(engine) = &self.engine else { return };
        let fuel = plugin.config.fuel_per_event;
        let mut live: Option<Live> = None;
        for (i, input) in inputs.iter().enumerate() {
            let Some(input) = input else { continue };
            add(&plugin.counters.calls, 1);
            let outcome = (|| {
                let l = match live.as_mut() {
                    Some(l) => l,
                    None => live.insert(Live::new(engine, loaded)?),
                };
                let (result, used) = l.call(fuel, input);
                add(&plugin.counters.total_fuel_used, used);
                let Some(bytes) = result? else {
                    return Ok(());
                };
                let output = parse_output(plugin.config.kind, &bytes)
                    .map_err(|m| Failure::output(l.memory_denied(), m))?;
                accept(i, output)
            })();
            if let Err(f) = outcome {
                live = None;
                plugin.record_failure(f);
            }
        }
    }

    /// Runs enrichment plugins in config order, appending
    /// `plugin:<name>:<tag>` tags (deduplicated). Never fails.
    pub fn enrich_batch(&self, events: &mut [CanonicalEvent]) {
        if self.runnable(PluginKind::Enrichment).next().is_none() {
            return;
        }
        let inputs: Vec<Option<Vec<u8>>> = events.iter().map(event_input).collect();
        for (plugin, loaded) in self.runnable(PluginKind::Enrichment) {
            let name = &plugin.config.name;
            self.run_plugin(plugin, loaded, &inputs, |i, out| {
                add(&plugin.counters.tags, out.tags.len() as u64);
                let tags = &mut events[i].tags;
                for t in out.tags {
                    let full = format!("plugin:{name}:{t}");
                    if !tags.contains(&full) {
                        tags.push(full);
                    }
                }
                Ok(())
            });
        }
    }

    /// Runs detection plugins in config order and returns their alerts.
    /// Never fails.
    pub fn detect_batch(&self, events: &[CanonicalEvent]) -> Vec<Alert> {
        let mut alerts = Vec::new();
        if self.runnable(PluginKind::Detection).next().is_none() {
            return alerts;
        }
        let inputs: Vec<Option<Vec<u8>>> = events.iter().map(event_input).collect();
        for (plugin, loaded) in self.runnable(PluginKind::Detection) {
            let cfg = &plugin.config;
            self.run_plugin(plugin, loaded, &inputs, |i, out| {
                let ev = &events[i];
                let built = out
                    .alerts
                    .into_iter()
                    .map(|a| {
                        Alert::new(
                            format!("plugin:{}:{}", cfg.name, a.id),
                            cfg.version,
                            cfg.sha256.clone(),
                            a.severity,
                            ev.timestamp,
                            ev.host_id,
                            a.reasons,
                            vec![ev.event_id],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Failure::new(FailureKind::Output, "alert rejected by schema"))?;
                add(&plugin.counters.alerts, built.len() as u64);
                alerts.extend(built);
                Ok(())
            });
        }
        alerts
    }

    /// Status of every configured plugin, in config order.
    pub fn status(&self) -> Vec<PluginStatus> {
        self.plugins
            .iter()
            .map(|p| {
                let c = &p.counters;
                let last = c
                    .last_failure
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                PluginStatus {
                    name: p.config.name.clone(),
                    kind: p.config.kind,
                    enabled: p.config.enabled,
                    sha256: p.config.sha256.clone(),
                    calls: c.calls.load(Relaxed),
                    alerts: c.alerts.load(Relaxed),
                    tags: c.tags.load(Relaxed),
                    failures_trap: c.failures_trap.load(Relaxed),
                    failures_fuel: c.failures_fuel.load(Relaxed),
                    failures_memory: c.failures_memory.load(Relaxed),
                    failures_output: c.failures_output.load(Relaxed),
                    last_failure_at: last.as_ref().map(|(_, at)| *at),
                    last_failure: last.map(|(m, _)| m),
                    total_fuel_used: c.total_fuel_used.load(Relaxed),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use osiris_schema::{
        EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    struct Spec {
        name: &'static str,
        kind: PluginKind,
        wasm: Vec<u8>,
        fuel: u64,
        mem: u32,
        enabled: bool,
    }

    fn spec(name: &'static str, kind: PluginKind, wasm: Vec<u8>) -> Spec {
        Spec {
            name,
            kind,
            wasm,
            fuel: 10_000_000,
            mem: 16,
            enabled: true,
        }
    }

    fn det(name: &'static str, fixture: &str) -> Spec {
        spec(name, PluginKind::Detection, fixtures::wasm(fixture))
    }

    fn enr(name: &'static str, fixture: &str) -> Spec {
        spec(name, PluginKind::Enrichment, fixtures::wasm(fixture))
    }

    /// Writes the modules to a tempdir and loads the set (dir kept alive).
    fn load_set(specs: Vec<Spec>) -> (tempfile::TempDir, PluginSet) {
        let dir = tempfile::tempdir().unwrap();
        let cfgs: Vec<PluginConfig> = specs
            .into_iter()
            .map(|s| {
                let path = dir.path().join(format!("{}.wasm", s.name));
                std::fs::write(&path, &s.wasm).unwrap();
                PluginConfig {
                    name: s.name.into(),
                    kind: s.kind,
                    path,
                    sha256: hex::encode(Sha256::digest(&s.wasm)),
                    version: 1,
                    fuel_per_event: s.fuel,
                    memory_max_mib: s.mem,
                    enabled: s.enabled,
                }
            })
            .collect();
        let set = PluginSet::load(&cfgs).unwrap();
        (dir, set)
    }

    fn event(process_name: &str) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1_700_000_000_000_000_000,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: EventType::ProcessExec.category(),
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", 300, 1),
                pid: 300,
                exe_path: format!("/usr/bin/{process_name}"),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            // Never handed to plugins.
            raw_event: Some(b"raw".to_vec()),
            relationships: vec![],
            tags: vec![],
            risk: None,
            // `ProcessRef` has no `name`; the fixture looks for `"name":"nc"` anywhere.
            event_data: serde_json::json!({ "process": { "name": process_name } }),
        }
    }

    fn status_of(set: &PluginSet, name: &str) -> PluginStatus {
        set.status().into_iter().find(|s| s.name == name).unwrap()
    }

    fn failures(s: &PluginStatus) -> u64 {
        s.failures_trap + s.failures_fuel + s.failures_memory + s.failures_output
    }

    #[test]
    fn warnings_are_rate_limited_to_one_per_60_s() {
        let last = AtomicU64::new(0);
        assert!(should_warn(&last, 1_000));
        assert!(!should_warn(&last, 1_000));
        assert!(!should_warn(&last, 1_059));
        assert!(should_warn(&last, 1_060));
        assert!(!should_warn(&last, 1_061));
    }

    #[test]
    fn plugin_set_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PluginSet>();
    }

    #[test]
    fn detection_plugin_alert_has_prefixed_rule_id() {
        let wasm = fixtures::wasm("detect_nc");
        let sha = hex::encode(Sha256::digest(&wasm));
        let (_d, set) = load_set(vec![spec("detect", PluginKind::Detection, wasm)]);
        let nc = event("nc");
        let alerts = set.detect_batch(std::slice::from_ref(&nc));
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.rule_id(), "plugin:detect:nc_seen");
        assert_eq!(a.rule_version(), 1);
        assert_eq!(a.rule_content_hash(), sha);
        assert_eq!(a.evidence(), &[nc.event_id]);
        assert_eq!(a.severity(), Severity::High);
        assert_eq!(a.timestamp(), nc.timestamp);
        assert_eq!(a.host_id(), nc.host_id);
        assert_eq!(a.reasons(), &["process is nc".to_string()]);

        assert!(set.detect_batch(&[event("bash")]).is_empty());
        assert!(!set.is_empty());
    }

    #[test]
    fn enrichment_adds_prefixed_deduplicated_tags() {
        let (_d, set) = load_set(vec![enr("tag", "tagger")]);
        let mut events = vec![event("bash"), event("nc")];
        events[0].tags.push("existing".into());
        set.enrich_batch(&mut events);
        set.enrich_batch(&mut events);
        assert_eq!(events[0].tags, vec!["existing", "plugin:tag:seen"]);
        assert_eq!(events[1].tags, vec!["plugin:tag:seen"]);
    }

    #[test]
    fn infinite_loop_is_stopped_and_next_event_still_evaluated() {
        let mut lp = det("loop", "infinite_loop");
        lp.fuel = 100_000;
        let (_d, set) = load_set(vec![lp, det("detect", "detect_nc")]);
        let events = vec![event("bash"), event("nc")];
        let start = std::time::Instant::now();
        let alerts = set.detect_batch(&events);
        let elapsed = start.elapsed();
        eprintln!("infinite_loop batch wall time: {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].evidence(), &[events[1].event_id]);
        let s = status_of(&set, "loop");
        assert_eq!(s.failures_fuel, 2);
        assert_eq!(s.calls, 2);
        assert_eq!(failures(&s), 2);
        assert!(s.total_fuel_used >= 200_000, "{}", s.total_fuel_used);
        assert!(s.last_failure.as_deref().unwrap().starts_with("fuel"));
        assert!(s.last_failure_at.is_some());
        assert_eq!(failures(&status_of(&set, "detect")), 0);
    }

    #[test]
    fn recursion_bomb_traps_without_crashing() {
        let (_d, set) = load_set(vec![det("rec", "recursion_bomb")]);
        assert!(set.detect_batch(&[event("nc"), event("nc")]).is_empty());
        let s = status_of(&set, "rec");
        eprintln!(
            "recursion_bomb: trap={} fuel={} last={:?}",
            s.failures_trap, s.failures_fuel, s.last_failure
        );
        assert!(s.failures_trap + s.failures_fuel >= 1, "{s:?}");
        assert_eq!(failures(&s), 2);
    }

    #[test]
    fn memory_bomb_hits_the_cap() {
        let mut mb = det("mem", "memory_bomb");
        mb.mem = 1;
        let (_d, set) = load_set(vec![mb]);
        assert!(set.detect_batch(&[event("nc")]).is_empty());
        let s = status_of(&set, "mem");
        assert_eq!(s.failures_memory, 1, "{s:?}");
        assert_eq!(failures(&s), 1);
        assert!(s.last_failure.as_deref().unwrap().starts_with("memory"));
    }

    #[test]
    fn out_of_bounds_output_is_an_output_failure() {
        let (_d, set) = load_set(vec![det("oob", "oob_output")]);
        assert!(set.detect_batch(&[event("nc")]).is_empty());
        let s = status_of(&set, "oob");
        assert_eq!(s.failures_output, 1, "{s:?}");
        assert_eq!(failures(&s), 1);
    }

    #[test]
    fn output_range_overflow_is_an_output_failure() {
        let (_d, set) = load_set(vec![det("ovf", "overflow_output")]);
        assert!(set.detect_batch(&[event("nc")]).is_empty());
        let s = status_of(&set, "ovf");
        assert_eq!(s.failures_output, 1, "{s:?}");
        assert_eq!(failures(&s), 1);
    }

    #[test]
    fn invalid_outputs_are_discarded_whole() {
        let ok_alert = r#"{"id":"ok","severity":"LOW","reasons":["fine"]}"#;
        let nine = format!(r#"{{"alerts":[{}]}}"#, [ok_alert; 9].join(","));
        let valid_and_bad_id = format!(
            r#"{{"alerts":[{ok_alert},{{"id":"Bad-Id","severity":"LOW","reasons":["SECRET"]}}]}}"#
        );
        let long_reason = format!(
            r#"{{"alerts":[{{"id":"a","severity":"LOW","reasons":["{}"]}}]}}"#,
            "x".repeat(600)
        );
        let cases: Vec<(&str, PluginKind, String)> = vec![
            ("nine alerts", PluginKind::Detection, nine),
            ("valid + bad id", PluginKind::Detection, valid_and_bad_id),
            ("600-byte reason", PluginKind::Detection, long_reason),
            (
                "unknown key",
                PluginKind::Detection,
                r#"{"alerts":[],"x":1}"#.into(),
            ),
            (
                "detection returning tags",
                PluginKind::Detection,
                r#"{"tags":["a"]}"#.into(),
            ),
            (
                "tag with a space",
                PluginKind::Enrichment,
                r#"{"tags":["ok","a b"]}"#.into(),
            ),
            (
                "enrichment returning alerts",
                PluginKind::Enrichment,
                format!(r#"{{"alerts":[{ok_alert}]}}"#),
            ),
            ("not json", PluginKind::Enrichment, "{tags".into()),
        ];
        for (case, kind, json) in cases {
            let (_d, set) = load_set(vec![spec("p", kind, fixtures::fixed_output(&json))]);
            let mut events = vec![event("nc")];
            set.enrich_batch(&mut events);
            let alerts = set.detect_batch(&events);
            assert!(alerts.is_empty(), "case `{case}`");
            assert!(events[0].tags.is_empty(), "case `{case}`");
            let s = status_of(&set, "p");
            assert_eq!(s.failures_output, 1, "case `{case}`: {s:?}");
            assert_eq!(failures(&s), 1, "case `{case}`");
            assert_eq!((s.alerts, s.tags), (0, 0), "case `{case}`");
            let lf = s.last_failure.unwrap();
            assert!(lf.starts_with("output"), "case `{case}`: {lf}");
            assert!(!lf.contains("SECRET") && !lf.contains("Bad-Id"), "{lf}");
        }
    }

    #[test]
    fn no_state_survives_across_batches() {
        let (_d, set) = load_set(vec![enr("c", "counter")]);
        let mut a = vec![event("bash")];
        let mut b = vec![event("bash")];
        set.enrich_batch(&mut a);
        set.enrich_batch(&mut b);
        assert_eq!(a[0].tags, vec!["plugin:c:n1"]);
        assert_eq!(b[0].tags, vec!["plugin:c:n1"]);

        // Within one batch the instance is reused.
        let mut both = vec![event("bash"), event("bash")];
        set.enrich_batch(&mut both);
        assert_eq!(both[0].tags, vec!["plugin:c:n1"]);
        assert_eq!(both[1].tags, vec!["plugin:c:n2"]);
    }

    /// Traps on the first call of each instance, then returns a tag. A fresh
    /// instance after the trap traps again; a reused one would not.
    fn trap_first_call() -> Vec<u8> {
        let out = r#"{"tags":["ok"]}"#;
        wat::parse_str(format!(
            r#"(module
                 (memory (export "memory") 1)
                 (global $n (mut i32) (i32.const 0))
                 (data (i32.const 16) "{out}")
                 (func (export "osiris_abi_version") (result i32) (i32.const 1))
                 (func (export "osiris_alloc") (param i32) (result i32) (i32.const 1024))
                 (func (export "osiris_on_event") (param i32 i32) (result i64)
                   (global.set $n (i32.add (global.get $n) (i32.const 1)))
                   (if (i32.eq (global.get $n) (i32.const 1)) (then unreachable))
                   (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const {len}))))"#,
            out = out.replace('"', "\\\""),
            len = out.len(),
        ))
        .unwrap()
    }

    #[test]
    fn instance_is_replaced_after_a_trap() {
        let (_d, set) = load_set(vec![spec("t", PluginKind::Enrichment, trap_first_call())]);
        let mut events = vec![event("bash"), event("bash")];
        set.enrich_batch(&mut events);
        assert!(events.iter().all(|e| e.tags.is_empty()));
        let s = status_of(&set, "t");
        assert_eq!(s.failures_trap, 2, "{s:?}");
        assert!(s.last_failure.as_deref().unwrap().starts_with("trap"));
    }

    #[test]
    fn disabled_plugin_is_not_run_but_listed() {
        let mut off = det("off", "detect_nc");
        off.enabled = false;
        let (_d, set) = load_set(vec![off, enr("tag", "tagger")]);
        let mut events = vec![event("nc")];
        set.enrich_batch(&mut events);
        assert!(set.detect_batch(&events).is_empty());
        let st = set.status();
        assert_eq!(
            st.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["off", "tag"]
        );
        assert!(!st[0].enabled);
        assert_eq!(st[0].calls, 0);
        assert!(st[1].enabled);
        assert_eq!(st[1].calls, 1);

        let mut only_off = det("off", "detect_nc");
        only_off.enabled = false;
        let (_d2, set2) = load_set(vec![only_off]);
        assert!(set2.is_empty());
        assert_eq!(set2.status().len(), 1);
        assert!(set2.detect_batch(&[event("nc")]).is_empty());
    }

    #[test]
    fn empty_config_is_empty() {
        let set = PluginSet::load(&[]).unwrap();
        assert!(set.is_empty());
        assert!(set.status().is_empty());
        let mut events = vec![event("nc")];
        set.enrich_batch(&mut events);
        assert!(set.detect_batch(&events).is_empty());
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut bad = det("p", "detect_nc");
        bad.fuel = 0;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.wasm");
        std::fs::write(&path, &bad.wasm).unwrap();
        let cfg = PluginConfig {
            name: "p".into(),
            kind: bad.kind,
            path,
            sha256: hex::encode(Sha256::digest(&bad.wasm)),
            version: 1,
            fuel_per_event: 0,
            memory_max_mib: 16,
            enabled: true,
        };
        let err = PluginSet::load(&[cfg]).err().unwrap();
        assert_eq!(err.plugin, "p");
    }

    #[test]
    fn status_counts_calls_alerts_tags_and_fuel() {
        let (_d, set) = load_set(vec![det("detect", "detect_nc"), enr("tag", "tagger")]);
        let mut events = vec![event("nc"), event("bash"), event("nc")];
        set.enrich_batch(&mut events);
        let alerts = set.detect_batch(&events);
        assert_eq!(alerts.len(), 2);

        let d = status_of(&set, "detect");
        assert_eq!(d.kind, PluginKind::Detection);
        assert!(d.enabled);
        assert_eq!((d.calls, d.alerts, d.tags), (3, 2, 0));
        assert_eq!(failures(&d), 0);
        assert!(d.total_fuel_used > 0);
        assert_eq!((&d.last_failure, d.last_failure_at), (&None, None));

        let t = status_of(&set, "tag");
        assert_eq!((t.calls, t.alerts, t.tags), (3, 0, 3));
        assert!(t.total_fuel_used > 0);

        let json = serde_json::to_value(&d).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        for k in [
            "name",
            "kind",
            "enabled",
            "sha256",
            "calls",
            "alerts",
            "tags",
            "failures_trap",
            "failures_fuel",
            "failures_memory",
            "failures_output",
            "last_failure",
            "last_failure_at",
            "total_fuel_used",
        ] {
            assert!(keys.contains(&k), "missing {k}");
        }
        assert_eq!(keys.len(), 14);
        assert_eq!(json["kind"], "detection");
    }
}
