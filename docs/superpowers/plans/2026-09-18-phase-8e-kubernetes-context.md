# Phase 8e Kubernetes Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `ContainerRef.pod_ref` from the node's own kubelet so container events (and per-process events in a container) carry pod name + namespace, and surface it in `GET /api/v1/containers` and the Console.

**Architecture:** A synchronous `PodLookup` trait in `osiris-pipeline` lets the pipeline attach `pod_ref` from an in-memory cache at the end of `process`. A new `osiris-k8s-context` crate provides the `PodCache` (implements `PodLookup`), a kubelet `/pods` parser, a hardened `KubeletClient`, and a refresher task. The Agent gates on Kubernetes detection, awaits one initial fetch before the pipeline starts, and spawns the refresher.

**Tech Stack:** Rust (tokio, tokio-util, reqwest 0.12, serde_json, axum for test mocks only), React/TypeScript/Vitest.

**Spec:** `docs/superpowers/specs/2026-09-18-phase-8e-kubernetes-context-design.md`

## Global Constraints

- No schema change: `osiris_schema::PodRef { pod_name: String, namespace: String }` and `ContainerRef.pod_ref: Option<PodRef>` already exist. No deployment/service owner.
- `PodLookup` lives in `osiris-pipeline` (pipeline must not depend on `reqwest`); `osiris-k8s-context` depends on `osiris-pipeline`, not the reverse.
- `Pipeline::process` stays synchronous; an existing `pod_ref` is never overwritten; an unknown container id leaves `pod_ref` as `None`.
- Constants (exact values): `MAX_CACHE_ENTRIES` = 10_000; `MAX_NAME_LEN` = 253 chars; `MAX_BODY_LEN` = 8 MiB (8 * 1024 * 1024); `FETCH_TIMEOUT` = 5s; default `refresh_secs` = 30; default kubelet URL `https://127.0.0.1:10250`; default token path `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- Names valid only if non-empty, no control characters, at most 253 chars; an invalid pod is skipped entirely. Over-cap bodies are a failure — never a truncated parse.
- The kubelet client uses `.no_proxy()`, never falls back to a default client (build failure → no client), TLS verification ON by default; `ca_path` adds a root CA; `insecure_skip_verify` is opt-in (default false). The token file is re-read on every fetch. The token is sent only over `https`, or over `http` to a loopback host.
- Every failure (connect, timeout, non-2xx, bad JSON, over-cap body, missing token file) degrades to "no pod_ref" + a `tracing::debug!`; never an error to the pipeline or agent boot. A failed refresh keeps the last good cache; a successful one replaces it entirely.
- Detection gate `k8s_context_active`: `enabled` AND (`kubelet_url` explicitly configured OR the token file exists). Off-cluster hosts make no connection to `127.0.0.1:10250`. Evaluated once at startup.
- Adding a field to `AgentConfig` breaks every struct literal: find them ALL with `grep -rn "AgentConfig {" crates` (currently `crates/osiris-agent/src/agent.rs` `base_config` and 8 in `crates/osiris-e2e-tests/tests/end_to_end.rs`), update each, then `cargo build --workspace --tests`. They set `k8s_context.enabled = false`.
- Before trusting `cargo test --workspace` after touching `osiris-agent`/`osiris-cli`/`osiris-server`, run `cargo build -p osiris-cli -p osiris-server -p osiris-agent` (e2e tests use prebuilt binaries).
- Test JSON containing control characters must use JSON escapes (`\u0007`), never raw bytes.
- The worktree guard refuses complex compound git commands: run git/cargo/npm as plain separate commands.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`. Subagent model: `sonnet` (haiku is org-blocked).

---

### Task 1: `PodLookup` trait and pipeline attach step

**Files:**
- Create: `crates/osiris-pipeline/src/pod_lookup.rs`
- Modify: `crates/osiris-pipeline/src/lib.rs` (module + re-export)
- Modify: `crates/osiris-pipeline/src/pipeline.rs` (field, builder, call in `process`, one test)

**Interfaces:**
- Produces (used by Tasks 2 and 4):
  - `pub trait PodLookup: Send + Sync { fn pod_for(&self, container_id: &str) -> Option<osiris_schema::PodRef>; }`
  - `pub fn attach_pod_ref(event: &mut CanonicalEvent, lookup: &dyn PodLookup)` (re-exported crate-wide as `osiris_pipeline::attach_pod_ref`)
  - `Pipeline::with_pod_lookup(self, lookup: std::sync::Arc<dyn PodLookup>) -> Self`

- [ ] **Step 1: Write the failing tests** — create `crates/osiris-pipeline/src/pod_lookup.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use osiris_schema::{Category, HostRef, PodRef};
    use osiris_sensor_api::{ContainerEventRaw, ContainerOperation, RawEvent, RawEventSource};
    use uuid::Uuid;

    use super::*;
    use crate::normalize::normalize;

    struct FakeLookup(HashMap<String, PodRef>);
    impl PodLookup for FakeLookup {
        fn pod_for(&self, container_id: &str) -> Option<PodRef> {
            self.0.get(container_id).cloned()
        }
    }

    fn host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    fn container_event(pod: Option<(&str, &str)>) -> osiris_schema::CanonicalEvent {
        let raw = RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: "c".repeat(64),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: "/kubepods/x".to_string(),
            pid: Some(10),
            pod_name: pod.map(|(n, _)| n.to_string()),
            pod_namespace: pod.map(|(_, ns)| ns.to_string()),
            timestamp_ns: 1,
            source: RawEventSource::Synthetic,
        });
        normalize(raw, &host(), "boot-1")
    }

    fn lookup_with(container_id: &str, name: &str, ns: &str) -> FakeLookup {
        let mut map = HashMap::new();
        map.insert(
            container_id.to_string(),
            PodRef { pod_name: name.to_string(), namespace: ns.to_string() },
        );
        FakeLookup(map)
    }

    #[test]
    fn fills_pod_ref_when_the_container_is_known_and_pod_ref_is_empty() {
        let mut event = container_event(None);
        assert!(event.container.as_ref().unwrap().pod_ref.is_none());
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        let pod = event.container.unwrap().pod_ref.unwrap();
        assert_eq!(pod.pod_name, "web-0");
        assert_eq!(pod.namespace, "prod");
    }

    #[test]
    fn never_overwrites_an_existing_pod_ref() {
        let mut event = container_event(Some(("original", "ns1")));
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        let pod = event.container.unwrap().pod_ref.unwrap();
        assert_eq!(pod.pod_name, "original");
        assert_eq!(pod.namespace, "ns1");
    }

    #[test]
    fn unknown_container_id_leaves_pod_ref_none() {
        let mut event = container_event(None);
        attach_pod_ref(&mut event, &lookup_with("other-id", "web-0", "prod"));
        assert!(event.container.unwrap().pod_ref.is_none());
    }

    #[test]
    fn events_without_a_container_are_untouched() {
        let mut event = container_event(None);
        event.container = None;
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        assert!(event.container.is_none());
    }

    #[test]
    fn works_for_any_category_such_as_a_per_process_event_in_a_container() {
        let mut event = container_event(None);
        event.category = Category::Process;
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        assert!(event.container.unwrap().pod_ref.is_some());
    }
}
```

Add a Pipeline-level test inside the existing `#[cfg(test)] mod tests` in `crates/osiris-pipeline/src/pipeline.rs` (add needed imports `use std::collections::HashMap; use std::sync::Arc; use osiris_schema::PodRef; use osiris_sensor_api::{ContainerEventRaw, ContainerOperation}; use crate::pod_lookup::PodLookup;` — check which are already imported in that module and add only the missing ones):

```rust
    struct FakePods(HashMap<String, PodRef>);
    impl PodLookup for FakePods {
        fn pod_for(&self, container_id: &str) -> Option<PodRef> {
            self.0.get(container_id).cloned()
        }
    }

    fn container_raw(container_id: &str) -> RawEvent {
        RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: container_id.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: "/kubepods/x".to_string(),
            pid: Some(10),
            pod_name: None,
            pod_namespace: None,
            timestamp_ns: 1,
            source: RawEventSource::Synthetic,
        })
    }

    #[test]
    fn pipeline_with_a_pod_lookup_attaches_pod_ref_and_without_one_leaves_it_none() {
        let id = "c".repeat(64);
        let mut pods = HashMap::new();
        pods.insert(id.clone(), PodRef { pod_name: "web-0".to_string(), namespace: "prod".to_string() });

        let mut with = Pipeline::new(test_host(), "boot-1".to_string()).with_pod_lookup(Arc::new(FakePods(pods)));
        let got = with.process(container_raw(&id));
        assert_eq!(got.event.container.unwrap().pod_ref.unwrap().pod_name, "web-0");

        let mut without = Pipeline::new(test_host(), "boot-1".to_string());
        let got = without.process(container_raw(&id));
        assert!(got.event.container.unwrap().pod_ref.is_none());
    }
```

Wire the module so it compiles: in `crates/osiris-pipeline/src/lib.rs` add `pub mod pod_lookup;` (alphabetical, after `pub mod pipeline;`) and `pub use pod_lookup::{attach_pod_ref, PodLookup};` (after the `pub use pipeline::...` line). Put ONLY the test module in `pod_lookup.rs` for now (no trait yet).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p osiris-pipeline pod`
Expected: compile FAIL (`PodLookup`, `attach_pod_ref`, `with_pod_lookup` not defined).

- [ ] **Step 3: Implement** — at the top of `pod_lookup.rs` (above the test module):

```rust
use osiris_schema::{CanonicalEvent, PodRef};

/// Resolves a container id to its Kubernetes pod (ARCHITECTURE.md §21.3).
/// Synchronous because `Pipeline::process` is: implementors serve from an
/// in-memory cache that a background task keeps fresh.
pub trait PodLookup: Send + Sync {
    fn pod_for(&self, container_id: &str) -> Option<PodRef>;
}

/// Attaches `pod_ref` to `event.container` when the event has a container,
/// its `pod_ref` is still `None`, and the lookup knows the container id.
/// An existing `pod_ref` is never overwritten. Category-agnostic: covers
/// both Container lifecycle events and per-process events whose container
/// came from the cgroup path.
pub fn attach_pod_ref(event: &mut CanonicalEvent, lookup: &dyn PodLookup) {
    let Some(container) = event.container.as_mut() else {
        return;
    };
    if container.pod_ref.is_some() {
        return;
    }
    container.pod_ref = lookup.pod_for(&container.container_id);
}
```

In `pipeline.rs`: add `use std::sync::Arc;` and `use crate::pod_lookup::{attach_pod_ref, PodLookup};` to the imports; add field `pod_lookup: Option<Arc<dyn PodLookup>>,` to `Pipeline`; in `Pipeline::new` add `pod_lookup: None,`; add the builder after `with_proc_root`:

```rust
    /// Attaches Kubernetes pod context to container events (Phase 8e) from
    /// the given lookup. Without one, `pod_ref` is left exactly as
    /// Normalize/Enrich produced it (builder shape of `with_proc_root`).
    pub fn with_pod_lookup(mut self, lookup: Arc<dyn PodLookup>) -> Self {
        self.pod_lookup = Some(lookup);
        self
    }
```

and in `process`, between the `enrich(...)` call and `validate(&mut event)`:

```rust
        if let Some(lookup) = &self.pod_lookup {
            attach_pod_ref(&mut event, lookup.as_ref());
        }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p osiris-pipeline`
Expected: all PASS (5 new unit tests + 1 pipeline test + existing).

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-pipeline
git commit -m "feat(pipeline): add PodLookup trait and pod_ref attach step

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `osiris-k8s-context` crate — `PodCache` and `parse_pod_list`

**Files:**
- Create: `crates/osiris-k8s-context/Cargo.toml`
- Create: `crates/osiris-k8s-context/src/lib.rs`
- Create: `crates/osiris-k8s-context/src/cache.rs`
- Create: `crates/osiris-k8s-context/src/parse.rs`
- (root `Cargo.toml` globs `crates/*`; no edit)

**Interfaces:**
- Consumes (Task 1): `osiris_pipeline::PodLookup`.
- Produces (used by Tasks 3-4):
  - `pub const MAX_CACHE_ENTRIES: usize = 10_000;` and `pub const MAX_NAME_LEN: usize = 253;`
  - `#[derive(Clone, Default)] pub struct PodCache` with `new() -> Self`, `replace(&self, map: HashMap<String, PodRef>)`, `len(&self) -> usize`, `is_empty(&self) -> bool`, `lookup(&self, container_id: &str) -> Option<PodRef>`; `impl PodLookup for PodCache`
  - `pub fn parse_pod_list(json: &str) -> Option<HashMap<String, PodRef>>`

- [ ] **Step 1: Manifest and lib wiring**

`Cargo.toml`:
```toml
[package]
name = "osiris-k8s-context"
version.workspace = true
edition.workspace = true

[dependencies]
serde_json = { workspace = true }
tracing = { workspace = true }
osiris-schema = { path = "../osiris-schema" }
osiris-pipeline = { path = "../osiris-pipeline" }
```

`src/lib.rs`:
```rust
//! Optional Kubernetes context enrichment (ARCHITECTURE.md §21.3): resolves
//! `container_id -> pod -> namespace` from the node's own kubelet and serves
//! it to the pipeline through `osiris_pipeline::PodLookup`. Any failure
//! degrades to "no pod_ref"; never a startup or pipeline failure.

mod cache;
mod parse;

pub use cache::{PodCache, MAX_CACHE_ENTRIES};
pub use parse::{parse_pod_list, MAX_NAME_LEN};
```

- [ ] **Step 2: Write the failing tests** — `src/cache.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use osiris_pipeline::PodLookup;
    use osiris_schema::PodRef;

    use super::*;

    fn pod(name: &str) -> PodRef {
        PodRef { pod_name: name.to_string(), namespace: "ns".to_string() }
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
        let big: HashMap<String, PodRef> =
            (0..MAX_CACHE_ENTRIES + 500).map(|i| (format!("id-{i}"), pod("p"))).collect();
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
```

`src/parse.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &str) -> String {
        format!(r#"{{"kind":"PodList","items":[{items}]}}"#)
    }

    fn pod_json(name: &str, ns: &str, statuses: &str) -> String {
        format!(r#"{{"metadata":{{"name":"{name}","namespace":"{ns}"}},"status":{{{statuses}}}}}"#)
    }

    #[test]
    fn strips_containerd_docker_and_crio_prefixes() {
        let json = list(&pod_json(
            "web-0",
            "prod",
            r#""containerStatuses":[
                {"containerID":"containerd://aaa"},
                {"containerID":"docker://bbb"},
                {"containerID":"cri-o://ccc"}
            ]"#,
        ));
        let map = parse_pod_list(&json).unwrap();
        for id in ["aaa", "bbb", "ccc"] {
            let pod = map.get(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(pod.pod_name, "web-0");
            assert_eq!(pod.namespace, "prod");
        }
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn includes_init_container_statuses() {
        let json = list(&pod_json(
            "job-1",
            "batch",
            r#""initContainerStatuses":[{"containerID":"containerd://init1"}],"containerStatuses":[{"containerID":"containerd://main1"}]"#,
        ));
        let map = parse_pod_list(&json).unwrap();
        assert!(map.contains_key("init1"));
        assert!(map.contains_key("main1"));
    }

    #[test]
    fn pod_without_statuses_contributes_nothing() {
        let json = list(&pod_json("pending", "ns", ""));
        assert!(parse_pod_list(&json).unwrap().is_empty());
    }

    #[test]
    fn status_without_a_container_id_or_with_an_empty_one_is_skipped() {
        let json = list(&pod_json(
            "p",
            "ns",
            r#""containerStatuses":[{"name":"x"},{"containerID":""},{"containerID":"containerd://"}]"#,
        ));
        assert!(parse_pod_list(&json).unwrap().is_empty());
    }

    #[test]
    fn invalid_names_skip_the_whole_pod() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        let statuses = r#""containerStatuses":[{"containerID":"containerd://k1"}]"#;
        let json = list(&format!(
            "{},{},{},{}",
            pod_json(&too_long, "ns", statuses),
            pod_json("bad\\u0007name", "ns", statuses),
            pod_json("", "ns", statuses),
            pod_json("ok", "ns", r#""containerStatuses":[{"containerID":"containerd://k2"}]"#),
        ));
        let map = parse_pod_list(&json).unwrap();
        assert!(!map.contains_key("k1"), "invalid-name pods must be skipped");
        assert_eq!(map.get("k2").unwrap().pod_name, "ok");
    }

    #[test]
    fn duplicate_container_ids_last_one_wins() {
        let statuses = r#""containerStatuses":[{"containerID":"containerd://dup"}]"#;
        let json = list(&format!("{},{}", pod_json("first", "ns", statuses), pod_json("second", "ns", statuses)));
        assert_eq!(parse_pod_list(&json).unwrap().get("dup").unwrap().pod_name, "second");
    }

    #[test]
    fn empty_and_null_item_lists_are_valid_and_empty() {
        assert!(parse_pod_list(r#"{"items":[]}"#).unwrap().is_empty());
        assert!(parse_pod_list(r#"{"items":null}"#).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_or_a_non_podlist_document_is_none() {
        assert!(parse_pod_list("not json").is_none());
        assert!(parse_pod_list(r#"{"message":"Unauthorized"}"#).is_none());
        assert!(parse_pod_list(r#"{"items":"nope"}"#).is_none());
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p osiris-k8s-context`
Expected: compile FAIL (`PodCache`, `parse_pod_list`, constants not defined).

- [ ] **Step 4: Implement `cache.rs`** — above its test module:

```rust
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
        self.inner.read().unwrap_or_else(|p| p.into_inner()).get(container_id).cloned()
    }
}

impl PodLookup for PodCache {
    fn pod_for(&self, container_id: &str) -> Option<PodRef> {
        self.lookup(container_id)
    }
}
```

- [ ] **Step 5: Implement `parse.rs`** — above its test module:

```rust
use std::collections::HashMap;

use osiris_schema::PodRef;

/// Longest pod/namespace name accepted (Kubernetes DNS-1123 subdomain limit).
pub const MAX_NAME_LEN: usize = 253;

/// Longest container id kept as a cache key (real ids are 64 hex chars).
const MAX_ID_LEN: usize = 128;

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= MAX_NAME_LEN && !s.chars().any(|c| c.is_control())
}

/// `containerd://<id>`, `docker://<id>`, `cri-o://<id>` -> `<id>`.
fn strip_runtime(container_id: &str) -> &str {
    container_id.split_once("://").map(|(_, rest)| rest).unwrap_or(container_id)
}

/// Parses a kubelet `GET /pods` `PodList` into `container_id -> PodRef`.
/// Pods with an invalid name/namespace are skipped entirely; statuses with
/// a missing/empty/oversized/control-char id are skipped. `None` when the
/// document is not a `PodList` (bad JSON, no `items`, `items` of the wrong
/// type); `"items": null` is a valid empty list.
pub fn parse_pod_list(json: &str) -> Option<HashMap<String, PodRef>> {
    let doc: serde_json::Value = serde_json::from_str(json).ok()?;
    let items = match doc.get("items")? {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Null => return Some(HashMap::new()),
        _ => return None,
    };

    let mut out = HashMap::new();
    for item in items {
        let Some(name) = item.pointer("/metadata/name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(namespace) = item.pointer("/metadata/namespace").and_then(|v| v.as_str()) else {
            continue;
        };
        if !valid_name(name) || !valid_name(namespace) {
            continue;
        }
        for key in ["containerStatuses", "initContainerStatuses"] {
            let Some(statuses) = item.pointer(&format!("/status/{key}")).and_then(|v| v.as_array()) else {
                continue;
            };
            for status in statuses {
                let Some(raw_id) = status.get("containerID").and_then(|v| v.as_str()) else {
                    continue;
                };
                let id = strip_runtime(raw_id);
                if id.is_empty() || id.chars().count() > MAX_ID_LEN || id.chars().any(|c| c.is_control()) {
                    continue;
                }
                out.insert(
                    id.to_string(),
                    PodRef { pod_name: name.to_string(), namespace: namespace.to_string() },
                );
            }
        }
    }
    Some(out)
}
```

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p osiris-k8s-context`
Expected: 5 cache + 8 parse tests PASS. `cargo clippy -p osiris-k8s-context --all-targets` → zero warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-k8s-context Cargo.lock
git commit -m "feat(k8s): add osiris-k8s-context crate with PodCache and kubelet PodList parser

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `KubeletClient` and refresher

**Files:**
- Modify: `crates/osiris-k8s-context/Cargo.toml` (deps)
- Create: `crates/osiris-k8s-context/src/kubelet.rs`
- Create: `crates/osiris-k8s-context/src/refresh.rs`
- Modify: `crates/osiris-k8s-context/src/lib.rs` (modules + re-exports)

**Interfaces:**
- Consumes (Task 2): `PodCache`, `parse_pod_list`.
- Produces (used by Task 4):
  - `pub const MAX_BODY_LEN: usize`, `pub const FETCH_TIMEOUT: Duration`
  - `pub struct KubeletConfig { pub url: String, pub token_path: PathBuf, pub ca_path: Option<PathBuf>, pub insecure_skip_verify: bool }`
  - `pub struct KubeletClient` with `pub fn new(cfg: KubeletConfig) -> Option<Self>` and `pub async fn fetch(&self) -> Option<HashMap<String, PodRef>>`
  - `pub(crate) fn token_may_be_sent(url: &reqwest::Url) -> bool`
  - `pub async fn refresh_once(client: &KubeletClient, cache: &PodCache) -> bool` (true when the cache was replaced)
  - `pub fn spawn_refresher(client: KubeletClient, cache: PodCache, interval: Duration, cancellation: CancellationToken) -> JoinHandle<()>` — sleeps `interval` THEN refreshes, repeating; the caller performs the initial fetch with `refresh_once`.

- [ ] **Step 1: Dependencies** — `crates/osiris-k8s-context/Cargo.toml` becomes:

```toml
[package]
name = "osiris-k8s-context"
version.workspace = true
edition.workspace = true

[dependencies]
reqwest = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tokio-util = { workspace = true }
tracing = { workspace = true }
osiris-schema = { path = "../osiris-schema" }
osiris-pipeline = { path = "../osiris-pipeline" }

[dev-dependencies]
axum = { workspace = true }
tempfile = { workspace = true }
```

In `lib.rs` add `mod kubelet;` `mod refresh;` and:
```rust
pub use kubelet::{KubeletClient, KubeletConfig, FETCH_TIMEOUT, MAX_BODY_LEN};
pub use refresh::{refresh_once, spawn_refresher};
```

- [ ] **Step 2: Write the failing tests** — `src/kubelet.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    use super::*;

    const POD_LIST: &str = r#"{"items":[{"metadata":{"name":"web-0","namespace":"prod"},"status":{"containerStatuses":[{"containerID":"containerd://abc"}]}}]}"#;

    #[derive(Clone)]
    pub(crate) struct Mock {
        pub expected_token: Arc<Mutex<String>>,
        pub body: Arc<Mutex<String>>,
        pub status: Arc<Mutex<u16>>,
    }

    impl Mock {
        pub(crate) fn new(token: &str, body: &str) -> Self {
            Self {
                expected_token: Arc::new(Mutex::new(token.to_string())),
                body: Arc::new(Mutex::new(body.to_string())),
                status: Arc::new(Mutex::new(200)),
            }
        }
    }

    async fn pods(State(mock): State<Mock>, headers: HeaderMap) -> impl IntoResponse {
        let expected = format!("Bearer {}", mock.expected_token.lock().unwrap());
        let ok = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected.as_str());
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let status = *mock.status.lock().unwrap();
        (StatusCode::from_u16(status).unwrap(), mock.body.lock().unwrap().clone()).into_response()
    }

    pub(crate) async fn serve(mock: Mock) -> String {
        let router = Router::new().route("/pods", get(pods)).with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    pub(crate) fn client_for(url: &str, token_file: &std::path::Path) -> KubeletClient {
        KubeletClient::new(KubeletConfig {
            url: url.to_string(),
            token_path: token_file.to_path_buf(),
            ca_path: None,
            insecure_skip_verify: false,
        })
        .expect("client")
    }

    fn token_file(dir: &tempfile::TempDir, token: &str) -> std::path::PathBuf {
        let path = dir.path().join("token");
        std::fs::write(&path, token).unwrap();
        path
    }

    #[tokio::test]
    async fn fetch_sends_the_bearer_token_and_parses_the_pod_list() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve(Mock::new("tok-1", POD_LIST)).await;
        let client = client_for(&base, &token_file(&dir, "tok-1\n"));
        let map = client.fetch().await.unwrap();
        assert_eq!(map.get("abc").unwrap().pod_name, "web-0");
        assert_eq!(map.get("abc").unwrap().namespace, "prod");
    }

    #[tokio::test]
    async fn wrong_token_is_a_401_and_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve(Mock::new("right", POD_LIST)).await;
        let client = client_for(&base, &token_file(&dir, "wrong"));
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn the_token_file_is_reread_on_every_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_file(&dir, "old");
        let mock = Mock::new("old", POD_LIST);
        let base = serve(mock.clone()).await;
        let client = client_for(&base, &path);
        assert!(client.fetch().await.is_some());

        *mock.expected_token.lock().unwrap() = "new".to_string();
        assert!(client.fetch().await.is_none(), "stale token must fail");
        std::fs::write(&path, "new").unwrap();
        assert!(client.fetch().await.is_some(), "rotated token must be picked up");
    }

    #[tokio::test]
    async fn non_2xx_malformed_json_and_missing_token_file_yield_none() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Mock::new("t", POD_LIST);
        let base = serve(mock.clone()).await;
        let client = client_for(&base, &token_file(&dir, "t"));

        *mock.status.lock().unwrap() = 500;
        assert!(client.fetch().await.is_none());
        *mock.status.lock().unwrap() = 200;

        *mock.body.lock().unwrap() = "not json".to_string();
        assert!(client.fetch().await.is_none());

        let missing = client_for(&base, &dir.path().join("no-such-token"));
        assert!(missing.fetch().await.is_none());
    }

    #[tokio::test]
    async fn an_over_cap_body_is_a_failure_never_a_truncated_parse() {
        let dir = tempfile::tempdir().unwrap();
        // A valid PodList prefix followed by padding past the cap: a truncated
        // parse would look valid, so the cap must fail the whole fetch.
        let big = format!(r#"{{"items":[],"pad":"{}"}}"#, "x".repeat(MAX_BODY_LEN + 10));
        let base = serve(Mock::new("t", &big)).await;
        let client = client_for(&base, &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_kubelet_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for("http://127.0.0.1:1", &token_file(&dir, "t"));
        assert!(client.fetch().await.is_none());
    }

    #[test]
    fn token_may_be_sent_over_https_or_to_loopback_only() {
        let ok = |u: &str| token_may_be_sent(&reqwest::Url::parse(u).unwrap());
        assert!(ok("https://10.0.0.5:10250"));
        assert!(ok("https://kubelet.example:10250"));
        assert!(ok("http://127.0.0.1:10255"));
        assert!(ok("http://localhost:10255"));
        assert!(ok("http://[::1]:10255"));
        assert!(!ok("http://10.0.0.5:10255"));
        assert!(!ok("http://kubelet.example:10255"));
    }

    #[test]
    fn new_rejects_bad_config() {
        let base = |url: &str, ca: Option<&str>| KubeletConfig {
            url: url.to_string(),
            token_path: "/t".into(),
            ca_path: ca.map(Into::into),
            insecure_skip_verify: false,
        };
        assert!(KubeletClient::new(base("not a url", None)).is_none());
        assert!(KubeletClient::new(base("ftp://x", None)).is_none());
        assert!(KubeletClient::new(base("https://127.0.0.1:10250", Some("/no/such/ca.pem"))).is_none());
        assert!(KubeletClient::new(base("https://127.0.0.1:10250", None)).is_some());
    }
}
```

`src/refresh.rs` (tests only for now):

```rust
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
```

NOTE for the implementer: the shared mock helpers (`Mock`, `serve`, `client_for`) are defined inside `kubelet.rs`'s `mod tests` as `pub(crate)`; for `refresh.rs` to import `crate::kubelet::tests::...`, declare that module as `#[cfg(test)] pub(crate) mod tests { ... }` in `kubelet.rs` (instead of a private `mod tests`).

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p osiris-k8s-context kubelet refresh`
Expected: compile FAIL (`KubeletClient`, `KubeletConfig`, `refresh_once`, `spawn_refresher`, `token_may_be_sent`, `MAX_BODY_LEN` not defined).

- [ ] **Step 4: Implement `kubelet.rs`** — above its test module:

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use osiris_schema::PodRef;

use crate::parse::parse_pod_list;

/// Largest kubelet `/pods` body accepted. Over the cap the whole fetch fails
/// (never a truncated parse).
pub const MAX_BODY_LEN: usize = 8 * 1024 * 1024;
/// Per-request timeout.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct KubeletConfig {
    /// Base URL, e.g. `https://127.0.0.1:10250`.
    pub url: String,
    /// Service-account token file, re-read on every fetch (projected tokens rotate).
    pub token_path: PathBuf,
    /// Extra root CA (PEM) to trust for the kubelet's serving certificate.
    pub ca_path: Option<PathBuf>,
    /// Opt-in: accept any kubelet certificate. Documented risk; default false.
    pub insecure_skip_verify: bool,
}

/// Fetches `GET <url>/pods` from the node's kubelet.
pub struct KubeletClient {
    pods_url: String,
    send_token: bool,
    token_path: PathBuf,
    client: reqwest::Client,
}

/// The bearer token may go over `https`, or over `http` only to a loopback host.
pub(crate) fn token_may_be_sent(url: &reqwest::Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Option<String>, reqwest::Error> {
    if resp.content_length().is_some_and(|n| n > MAX_BODY_LEN as u64) {
        return Ok(None);
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > MAX_BODY_LEN {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

impl KubeletClient {
    /// `None` when the URL is not http(s), the CA file is unreadable/invalid,
    /// or the HTTP client cannot be built — never a fallback to a default
    /// (proxy-honouring, unbounded) client.
    pub fn new(cfg: KubeletConfig) -> Option<Self> {
        let url = reqwest::Url::parse(&cfg.url).ok()?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return None;
        }
        let mut builder = reqwest::Client::builder().timeout(FETCH_TIMEOUT).no_proxy();
        if let Some(ca_path) = &cfg.ca_path {
            let pem = std::fs::read(ca_path).ok()?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).ok()?);
        }
        if cfg.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = match builder.build() {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %e, "could not build the kubelet HTTP client; pod context disabled");
                return None;
            }
        };
        Some(Self {
            pods_url: format!("{}/pods", url.as_str().trim_end_matches('/')),
            send_token: token_may_be_sent(&url),
            token_path: cfg.token_path,
            client,
        })
    }

    /// `Some(map)` on success; `None` (with a debug log) on any failure.
    pub async fn fetch(&self) -> Option<HashMap<String, PodRef>> {
        if !self.send_token {
            tracing::debug!("refusing to send the service-account token over plain http to a non-loopback kubelet");
            return None;
        }
        let token = match std::fs::read_to_string(&self.token_path) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            Ok(_) => {
                tracing::debug!("kubelet token file is empty");
                return None;
            }
            Err(e) => {
                tracing::debug!(error = %e, "could not read the kubelet token file");
                return None;
            }
        };
        let resp = match self.client.get(&self.pods_url).bearer_auth(&token).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "kubelet request failed");
                return None;
            }
        };
        let resp = match resp.error_for_status() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "kubelet returned an error status");
                return None;
            }
        };
        let body = match read_capped(resp).await {
            Ok(Some(body)) => body,
            Ok(None) => {
                tracing::debug!("kubelet response exceeded the size cap");
                return None;
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed reading the kubelet response");
                return None;
            }
        };
        let parsed = parse_pod_list(&body);
        if parsed.is_none() {
            tracing::debug!("kubelet response was not a PodList");
        }
        parsed
    }
}
```

Change `mod tests` in this file to `#[cfg(test)] pub(crate) mod tests` (see the NOTE in Step 2).

- [ ] **Step 5: Implement `refresh.rs`** — above its test module:

```rust
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
```

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p osiris-k8s-context`
Expected: all PASS (Task 2's 13 + 8 kubelet + 3 refresh). `cargo clippy -p osiris-k8s-context --all-targets` → zero warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-k8s-context Cargo.lock
git commit -m "feat(k8s): add hardened kubelet client and cache refresher

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Agent config, detection gate and startup wiring

**Files:**
- Modify: `crates/osiris-agent/Cargo.toml` (add `osiris-k8s-context`)
- Modify: `crates/osiris-agent/src/config.rs` (`K8sContextConfig`, `AgentConfig.k8s_context`, tests)
- Create: `crates/osiris-agent/src/k8s.rs`
- Modify: `crates/osiris-agent/src/lib.rs` (`pub mod k8s;`, re-export `K8sContextConfig`)
- Modify: `crates/osiris-agent/src/agent.rs` (wire into `Agent::start`, update `base_config`, add integration tests)
- Modify: every `AgentConfig { ... }` literal: `crates/osiris-e2e-tests/tests/end_to_end.rs` (8 sites)

**Interfaces:**
- Consumes (Tasks 1-3): `osiris_pipeline::Pipeline::with_pod_lookup`, `osiris_k8s_context::{PodCache, KubeletClient, KubeletConfig, refresh_once, spawn_refresher}`.
- Produces:
  - `pub struct K8sContextConfig { pub enabled: bool, pub kubelet_url: Option<String>, pub token_path: Option<String>, pub ca_path: Option<String>, pub insecure_skip_verify: bool, pub refresh_secs: u64 }` (`Deserialize`, `Clone`, `Debug`, `Default`), `AgentConfig.k8s_context: K8sContextConfig` (`#[serde(default)]`)
  - `pub const DEFAULT_SA_TOKEN_PATH`, `pub const DEFAULT_KUBELET_URL` in `k8s.rs`
  - `pub fn k8s_context_active(cfg: &K8sContextConfig) -> bool`
  - `pub async fn start_pod_cache(cfg: &K8sContextConfig, cancellation: &CancellationToken) -> Option<(PodCache, JoinHandle<()>)>`

- [ ] **Step 1: Dependency** — `crates/osiris-agent/Cargo.toml` `[dependencies]`:

```toml
osiris-k8s-context = { path = "../osiris-k8s-context" }
```

- [ ] **Step 2: Write the failing config tests** — append to `mod tests` in `crates/osiris-agent/src/config.rs`:

```rust
    #[test]
    fn k8s_context_defaults_so_pre_8e_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\n").unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.k8s_context.enabled);
        assert!(config.k8s_context.kubelet_url.is_none());
        assert!(config.k8s_context.token_path.is_none());
        assert!(config.k8s_context.ca_path.is_none());
        assert!(!config.k8s_context.insecure_skip_verify);
        assert_eq!(config.k8s_context.refresh_secs, 30);
    }

    #[test]
    fn k8s_context_section_parses_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\nk8s_context:\n  enabled: false\n  kubelet_url: https://10.0.0.1:10250\n  ca_path: /ca.pem\n  refresh_secs: 5\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(!config.k8s_context.enabled);
        assert_eq!(config.k8s_context.kubelet_url.as_deref(), Some("https://10.0.0.1:10250"));
        assert_eq!(config.k8s_context.ca_path.as_deref(), Some("/ca.pem"));
        assert_eq!(config.k8s_context.refresh_secs, 5);
    }
```

- [ ] **Step 3: Write the failing gate + integration tests** — create `crates/osiris-agent/src/k8s.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
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
                    (axum::http::StatusCode::OK, body).into_response_compat()
                } else {
                    axum::http::StatusCode::UNAUTHORIZED.into_response_compat()
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
```

In the test above, replace the `.into_response_compat()` placeholders with the axum idiom: add `use axum::response::IntoResponse;` to the test imports and write `(axum::http::StatusCode::OK, body).into_response()` / `axum::http::StatusCode::UNAUTHORIZED.into_response()`.

Add `pub mod k8s;` to `crates/osiris-agent/src/lib.rs` and change the config re-export to `pub use config::{AgentConfig, CloudMetadataConfig, K8sContextConfig};`.

Add the two end-to-end agent tests in the `tests` module of `crates/osiris-agent/src/agent.rs` (next to `synthetic_events_reach_the_spool_file`). The synthetic `container_deploy_in_remote_session` scenario emits Container events with container id `"d00d".repeat(16)`:

```rust
    async fn kubelet_mock_serving(container_id: &str) -> String {
        use axum::routing::get;
        let body = format!(
            r#"{{"items":[{{"metadata":{{"name":"web-0","namespace":"prod"}},"status":{{"containerStatuses":[{{"containerID":"containerd://{container_id}"}}]}}}}]}}"#
        );
        let router = axum::Router::new().route("/pods", get(move || {
            let body = body.clone();
            async move { body }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn container_events_in_the_spool_carry_the_pod_ref_when_k8s_context_is_active() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "tok").unwrap();
        let base = kubelet_mock_serving(&"d00d".repeat(16)).await;

        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("container_deploy_in_remote_session".to_string());
        config.k8s_context = crate::config::K8sContextConfig {
            enabled: true,
            kubelet_url: Some(base),
            token_path: Some(token_path.to_string_lossy().to_string()),
            refresh_secs: 3600,
            ..Default::default()
        };
        let agent = Agent::start(config, test_host(), "boot-1".to_string()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert!(contents.contains("\"pod_name\":\"web-0\""), "spool must carry the resolved pod: {contents}");
        assert!(contents.contains("\"namespace\":\"prod\""));
    }

    #[tokio::test]
    async fn without_k8s_context_the_spool_has_no_pod_ref() {
        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.ndjson");
        let mut config = base_config(&dir);
        config.enable_synthetic = true;
        config.synthetic_scenario = Some("container_deploy_in_remote_session".to_string());
        // base_config leaves k8s_context disabled.
        let agent = Agent::start(config, test_host(), "boot-1".to_string()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        agent.shutdown().await;

        let contents = tokio::fs::read_to_string(&spool_path).await.unwrap();
        assert!(!contents.contains("\"pod_name\""));
    }
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p osiris-agent k8s`
Expected: compile FAIL (`K8sContextConfig`, `k8s_context_active`, `start_pod_cache`, `AgentConfig.k8s_context` not defined).

- [ ] **Step 5: Implement config** — in `crates/osiris-agent/src/config.rs`, next to `CloudMetadataConfig`:

```rust
/// Optional Kubernetes context (Phase 8e, ARCHITECTURE.md §21.3): resolves
/// container -> pod from the node's kubelet. On by default but active only
/// when a kubelet URL is configured or a service-account token exists, so a
/// non-Kubernetes host makes no connection. TLS verification is on; use
/// `ca_path` for the kubelet's CA, or `insecure_skip_verify` (a documented
/// risk) as an explicit opt-in.
#[derive(Debug, Clone, Deserialize)]
pub struct K8sContextConfig {
    #[serde(default = "default_k8s_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub kubelet_url: Option<String>,
    #[serde(default)]
    pub token_path: Option<String>,
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default = "default_k8s_refresh_secs")]
    pub refresh_secs: u64,
}

fn default_k8s_enabled() -> bool {
    true
}

fn default_k8s_refresh_secs() -> u64 {
    30
}

impl Default for K8sContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kubelet_url: None,
            token_path: None,
            ca_path: None,
            insecure_skip_verify: false,
            refresh_secs: 30,
        }
    }
}
```

and in `AgentConfig` (next to `cloud_metadata`):

```rust
    /// Kubernetes context (Phase 8e). Defaults to enabled-but-gated, so
    /// every pre-8e agent.yaml still loads.
    #[serde(default)]
    pub k8s_context: K8sContextConfig,
```

- [ ] **Step 6: Implement `k8s.rs`** — above its tests:

```rust
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
```

- [ ] **Step 7: Wire `Agent::start`** — in `crates/osiris-agent/src/agent.rs`, replace the pipeline construction and task list:

```rust
        let mut pipeline = Pipeline::new(host, boot_id).with_proc_root(proc_root);
        let k8s_refresher = match crate::k8s::start_pod_cache(&config.k8s_context, &cancellation).await {
            Some((cache, handle)) => {
                pipeline = pipeline.with_pod_lookup(Arc::new(cache));
                Some(handle)
            }
            None => None,
        };
```

(the existing `let pipeline_cancellation = ...` / spawn stays unchanged), and change the `background_tasks` initializer:

```rust
        let mut tasks = vec![pipeline_handle, drain_handle];
        tasks.extend(k8s_refresher);
```

then use `tokio::sync::Mutex::new(tasks)` in place of `vec![pipeline_handle, drain_handle]`.

- [ ] **Step 8: Update every `AgentConfig` literal** — `grep -rn "AgentConfig {" crates`; add to each literal:
- `crates/osiris-agent/src/agent.rs` `base_config`: `k8s_context: crate::config::K8sContextConfig { enabled: false, ..Default::default() },`
- the 8 literals in `crates/osiris-e2e-tests/tests/end_to_end.rs`: `k8s_context: osiris_agent::K8sContextConfig { enabled: false, ..Default::default() },`
Do not touch `pub struct AgentConfig {`.

- [ ] **Step 9: Run tests and workspace build**

Run: `cargo test -p osiris-agent` → all PASS (2 config + 7 k8s + 2 agent integration + existing).
Run: `cargo build --workspace --tests` → no errors (proves no literal was missed).
Run: `cargo clippy -p osiris-agent -p osiris-k8s-context -p osiris-pipeline --all-targets` → zero warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-agent crates/osiris-e2e-tests Cargo.lock
git commit -m "feat(agent): gate and start Kubernetes pod context, attach pod_ref in the pipeline

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: `/api/v1/containers` pod fields and Console column

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (`ContainerSummary` ~line 648, `containers_handler` ~line 789, tests)
- Modify: `console/src/api/types.ts` (`ContainerSummary`)
- Modify: `console/src/screens/containers/ContainerList.tsx`
- Modify: `console/src/screens/containers/ContainerList.test.tsx`

**Interfaces:**
- Consumes: `osiris_schema::PodRef` on the kept (most-recent) event's `container.pod_ref`.
- Produces: JSON fields `pod_name`, `pod_namespace` (each string or `null`) on every `/api/v1/containers` row; TS `ContainerSummary` gains `pod_name?: string | null` and `pod_namespace?: string | null`.

- [ ] **Step 1: Write the failing backend tests** — in the tests module of `crates/osiris-api/src/lib.rs`, after `containers_endpoint_dedups_by_container_id_alone_not_host` (use the existing `container_event` helper and `test_storage()`):

```rust
    #[tokio::test]
    async fn containers_endpoint_carries_pod_fields_from_the_kept_event() {
        let (_dir, storage) = test_storage();
        let mut event = container_event("abc", EventType::ContainerStart, 1000);
        event.container.as_mut().unwrap().pod_ref = Some(osiris_schema::PodRef {
            pod_name: "web-0".to_string(),
            namespace: "prod".to_string(),
        });
        storage.write(&event).unwrap();

        let Json(rows) = containers_handler(State(storage)).await.unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pod_name.as_deref(), Some("web-0"));
        assert_eq!(rows[0].pod_namespace.as_deref(), Some("prod"));
    }

    #[tokio::test]
    async fn containers_endpoint_pod_fields_are_null_when_absent() {
        let (_dir, storage) = test_storage();
        storage.write(&container_event("abc", EventType::ContainerStart, 1000)).unwrap();

        let Json(rows) = containers_handler(State(storage)).await.unwrap();

        assert!(rows[0].pod_name.is_none());
        let json = serde_json::to_value(&rows[0]).unwrap();
        assert!(json["pod_name"].is_null());
        assert!(json["pod_namespace"].is_null());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p osiris-api containers_endpoint`
Expected: compile FAIL (no `pod_name` field on `ContainerSummary`).

- [ ] **Step 3: Implement backend** — add to `ContainerSummary` (after `timestamp`):

```rust
    pod_name: Option<String>,
    pod_namespace: Option<String>,
```

and in `containers_handler`, before `seen.insert(...)`:

```rust
                let (pod_name, pod_namespace) = match &container.pod_ref {
                    Some(pod) => (Some(pod.pod_name.clone()), Some(pod.namespace.clone())),
                    None => (None, None),
                };
```

then add `pod_name, pod_namespace,` to the `ContainerSummary { ... }` literal. Grep `ContainerSummary {` in `crates/osiris-api` for any other construction and update it. Add one line to the handler's doc comment: "Pod fields (Phase 8e) come from the kept event's `container.pod_ref` only; a later event without one shows null until an event carrying it becomes the latest."

- [ ] **Step 4: Run backend tests**

Run: `cargo test -p osiris-api`
Expected: all PASS (existing + 2 new).

- [ ] **Step 5: Write the failing Console test** — append inside `describe("ContainerList", ...)` in `ContainerList.test.tsx`:

```tsx
  it("renders a Pod column as namespace/pod, and a dash when there is no pod", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [
          { container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000, pod_name: "web-0", pod_namespace: "prod" },
          { container_id: "def456", host_id: "h1", hostname: "host-a", image: "redis:7", status: "RUNNING", timestamp: 900, pod_name: null, pod_namespace: null },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByRole("columnheader", { name: "Pod" })).toBeInTheDocument();
    expect(screen.getByText("prod/web-0")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });
```

- [ ] **Step 6: Run to verify it fails**

Run (from `console/`): `npx vitest run src/screens/containers/ContainerList.test.tsx`
Expected: FAIL (no "Pod" column header).

- [ ] **Step 7: Implement Console** — `types.ts` `ContainerSummary` gains (after `timestamp`):

```ts
  pod_name?: string | null;
  pod_namespace?: string | null;
```

`ContainerList.tsx`: add `import type { ContainerSummary } from "../../api/types";`, a module-level helper above `ContainerList`:

```tsx
// Phase 8e: pod context from the node's kubelet, or a dash for containers
// with no resolved pod (non-Kubernetes hosts, or a container the kubelet
// cache does not know).
function formatPod(row: ContainerSummary): string {
  if (!row.pod_name) return "—";
  return row.pod_namespace ? `${row.pod_namespace}/${row.pod_name}` : row.pod_name;
}
```

a header `<th>Pod</th>` after the Status header, and the cell `<td>{formatPod(row)}</td>` after the status cell.

- [ ] **Step 8: Run Console tests and build**

Run (from `console/`): `npx vitest run` → all PASS (220 existing + 1 new). If `node_modules` is missing in the worktree, run `npm ci` first (do not commit any `package*.json` change).
Run: `npm run build` → tsc + vite clean.

- [ ] **Step 9: Full verification**

Run: `cargo build -p osiris-cli -p osiris-server -p osiris-agent`, then `cargo test --workspace` → all green.

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-api console/src
git commit -m "feat(containers): surface pod name and namespace in the container list

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** §3.1 `PodLookup` in the pipeline → Task 1; §3.2 `PodCache`/`parse_pod_list`/`KubeletClient`/refresher (caps, name validation, token rules, no_proxy, no fallback, ca/insecure, stale-while-error) → Tasks 2-3; §3.3 `with_pod_lookup` + `attach_pod_ref` (no overwrite, category-agnostic) → Task 1; §3.4 config section, gate, agent wiring, literals → Task 4; §3.5 API + Console → Task 5; §4 error handling/security → Tasks 2-3 (each failure path tested); §5 tests → mock kubelet (success/401/non-2xx/malformed/over-cap/rotation), parser cases, cache/refresher (stale, vanish, cap, cancel), token-safety unit, pipeline, agent gate + two spool integration tests, API null/present, Console column; §6 Non-Goals honored.

**Deliberate deviation from spec wording (ruling):** the spec says the refresher "fetches immediately then every interval"; the plan has the caller do the awaited initial `refresh_once` (so the cache is warm before the pipeline starts, avoiding a startup race) and `spawn_refresher` sleeps first. Observable behavior is the same.

**Placeholders:** none; the two test snippets that used a `.into_response_compat()` stand-in in Task 4 Step 3 are explicitly replaced by the real axum idiom in the same step.

**Type consistency:** `PodLookup::pod_for`, `attach_pod_ref`, `with_pod_lookup`, `PodCache::{new,replace,len,is_empty,lookup}`, `parse_pod_list`, `KubeletConfig{url,token_path,ca_path,insecure_skip_verify}`, `KubeletClient::{new,fetch}`, `refresh_once`, `spawn_refresher`, `K8sContextConfig` fields, `k8s_context_active`, `start_pod_cache`, `pod_name`/`pod_namespace` are spelled identically across tasks.
