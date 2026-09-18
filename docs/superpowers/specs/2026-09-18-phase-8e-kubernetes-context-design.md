# Phase 8e: Kubernetes Context — Design

Date: 2026-09-18. Status: approved in chat, pending written-spec review.
Source: ARCHITECTURE.md §21.3 (Kubernetes context), §9.2 (`ContainerRef.pod_ref`), §93 (Phase 8).
Predecessor: Phase 8d (Cloud Metadata Probe) — same optional-enrichment posture.

## 1. Scope

Phase 8 decomposition: 8a RBAC/auth, 8b Response Engine v1, 8c Host Registry, 8d Cloud metadata,
**8e (this phase): Kubernetes context**, 8f multi-tenant `tenant_id` scoping.

8e populates `ContainerRef.pod_ref: Option<PodRef>` by resolving `container_id → pod → namespace`
from the node's own kubelet. It is an **optional** enrichment: absence degrades to container-level
context (§21.3), never a startup or pipeline failure.

Today `pod_ref` is always `None`:
- `normalize_container_event` (`crates/osiris-pipeline/src/normalize.rs`) builds it from
  `raw.pod_name`/`raw.pod_namespace`, which the container poller
  (`crates/osiris-sensors/container/src/poller.rs`) always sets to `None`.
- `NsCgroupResolver::resolve_uncached` (`ns_cgroup_resolver.rs`) hardcodes `pod_ref: None` for
  per-process events.

## 2. Schema

No schema change. `PodRef { pod_name: String, namespace: String }` and
`ContainerRef.pod_ref: Option<PodRef>` already exist (`crates/osiris-schema/src/entities.rs`).
Deployment/service owner is NOT added (YAGNI; `PodRef` has no such fields).

## 3. Components

### 3.1 `PodLookup` trait — in `osiris-pipeline`
```rust
pub trait PodLookup: Send + Sync {
    fn pod_for(&self, container_id: &str) -> Option<PodRef>;
}
```
Lives in `osiris-pipeline` so the pipeline does not depend on `reqwest`; the k8s crate depends
on the pipeline, not the reverse. `Pipeline::process` is synchronous, so the lookup is a
synchronous in-memory read.

### 3.2 New crate `osiris-k8s-context`
One crate per subsystem (pattern of `osiris-auth`, `osiris-response`, `osiris-cloud-context`).

- `PodCache`: cheap-clone handle over `Arc<RwLock<HashMap<String, PodRef>>>`;
  `lookup`, `replace(map)`, `len`; implements `PodLookup`. Capped at `MAX_CACHE_ENTRIES` = 10_000
  (entries beyond the cap are dropped on `replace`).
- `parse_pod_list(json: &str) -> Option<HashMap<String, PodRef>>`: parses a kubelet `PodList`
  (`items[].metadata.{name,namespace}` and `items[].status.{containerStatuses,initContainerStatuses}[].containerID`).
  The runtime prefix (`containerd://`, `docker://`, `cri-o://`) is stripped; the remainder is
  the key. Pods without statuses contribute nothing. Names are validated: non-empty, no control
  characters, at most `MAX_NAME_LEN` = 253 chars, else that pod's entries are skipped.
  Malformed JSON → `None`.
- `KubeletClient`: `GET <kubelet_url>/pods` with `Authorization: Bearer <token>`; token file is
  re-read on every fetch (projected tokens rotate). Response body capped at `MAX_BODY_LEN` =
  8 MiB (over-cap → failure, never a truncated parse). Request timeout `FETCH_TIMEOUT` = 5s.
  Client built with `.no_proxy()`; building may fail → the fetch fails (no fallback to a default
  client). Optional CA via `ca_path`; `insecure_skip_verify` is opt-in only.
  The token is sent only over `https`, or over `http` when the host is a loopback address.
- `spawn_refresher(client, cache, refresh_interval, cancellation) -> JoinHandle<()>`: fetch
  immediately, then every interval until cancelled. Success replaces the whole cache (so
  containers that disappeared drop out). Failure keeps the last good cache (stale-while-error)
  and logs at debug.

### 3.3 Pipeline integration
`Pipeline::with_pod_lookup(mut self, lookup: Arc<dyn PodLookup>) -> Self` (builder shape of
`with_proc_root`). At the end of `Pipeline::process`, after `enrich`, a step
`attach_pod_ref(&mut event, lookup)` sets `event.container.pod_ref` when the event has a
`container`, its `pod_ref` is `None`, and the lookup resolves its `container_id`. An existing
`pod_ref` is never overwritten. This covers both container-lifecycle events and per-process
events whose container came from the cgroup path.

### 3.4 Agent
New optional `k8s_context` section in `AgentConfig` (`#[serde(default)]`, so pre-8e configs load):

| Field | Default |
|---|---|
| `enabled` | `true` |
| `kubelet_url` | none (effective `https://127.0.0.1:10250`) |
| `token_path` | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| `ca_path` | none |
| `insecure_skip_verify` | `false` |
| `refresh_secs` | `30` |

Detection gate (`k8s_context_active`): `enabled` AND (`kubelet_url` explicitly configured OR the
token file exists). Off a Kubernetes node nothing connects to `127.0.0.1:10250`.
When active, `Agent::start` creates the `PodCache`, builds the pipeline with
`with_pod_lookup`, and registers the refresher task in `background_tasks` under the agent's
cancellation token. When inactive, behavior is exactly as before 8e.
Adding a field to `AgentConfig` breaks every struct literal: update all of them (find with
`grep -rn "AgentConfig {" crates`); e2e literals set `k8s_context.enabled = false`.

### 3.5 API and Console
`ContainerSummary` (`GET /api/v1/containers`) gains `pod_name: Option<String>` and
`pod_namespace: Option<String>` (serialized as `null` when absent), read from the kept
(most-recent) event's `container.pod_ref`. Console `ContainerSummary` type gains the optional
nullable fields and `ContainerList` gains a "Pod" column (`namespace/pod_name`, `—` when absent).
Story screens need nothing: the event JSON already carries `container.pod_ref`.

## 4. Error handling and security

- Every failure (connect, timeout, non-2xx, malformed JSON, over-cap body, missing token file)
  degrades to "no pod_ref" with a debug log; never an error to the pipeline or agent boot.
- Kubelet content is treated as untrusted: name validation, entry cap, body cap, no truncated parse.
- TLS verification is ON by default. Kubelet serving certs are often self-signed: operators
  either provide `ca_path` or set `insecure_skip_verify: true` (documented as a risk). Without
  either, the fetch fails to "no pod_ref"; it never silently accepts any certificate.
- The service-account token is never sent over plain http to a non-loopback host.
- Required RBAC (documented only, no manifests shipped): the agent's service account needs
  `get` on `nodes/proxy` to call the kubelet's `/pods`.

## 5. Testing

- Mock kubelet (axum, local port): requires the Bearer token; cases: success, 401, non-2xx,
  malformed JSON, over-cap body, token rotated between fetches (second fetch uses the new token).
- Parser: containerd/docker/cri-o prefixes, init containers, pod with no statuses, invalid names
  skipped, duplicate container ids, empty list.
- Cache/refresher: failure keeps the last good cache; success removes vanished containers;
  cap enforced; refresher stops on cancellation.
- Token safety: plain http to a non-loopback host refuses to send the token.
- Pipeline: a container event gets `pod_ref`; a per-process event whose container came from the
  cgroup path gets it; an existing `pod_ref` is not overwritten; unknown id stays `None`.
- Agent: config defaults/old-config-loads; gate cases (disabled, no token and no url, url set,
  token file present); e2e literals disabled.
- API: `ContainerSummary` carries pod fields from the kept event and serializes `null` when
  absent. Console: Pod column with and without data.
- Full workspace + console suites green; rebuild `osiris-cli`/`osiris-server`/`osiris-agent`
  before trusting `osiris-e2e-tests`.

## 6. Non-Goals

Deployment/service/owner resolution; API-server watch; CRI socket; pod labels/UID; Kubernetes
events; shipping RBAC manifests; periodic re-evaluation of the detection gate (evaluated once at
startup); multi-tenant scoping (8f); Windows/non-Linux nodes.
