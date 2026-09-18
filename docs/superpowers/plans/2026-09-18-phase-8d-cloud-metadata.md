# Phase 8d Cloud Metadata Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `HostRef.cloud` at Agent startup by probing AWS IMDSv2, Azure IMDS and GCP metadata, and surface it in `GET /api/v1/hosts` and the Console Host Registry.

**Architecture:** New `osiris-cloud-context` crate holds a `CloudMetadataProvider` trait, three provider impls (each with an injectable base URL) and a `detect()` that probes all providers concurrently under a per-provider timeout. The Agent calls it once at startup (config-gated, overridable base URLs) and stores the result in the `HostRef` that already rides on every event. The API reads `event.host.cloud` off the most recent event per host; the Console adds a column. No schema or storage change.

**Tech Stack:** Rust (tokio, reqwest 0.12 async, async-trait, futures-util, axum for test mocks only), React/TypeScript/Vitest for the Console.

**Spec:** `docs/superpowers/specs/2026-09-18-phase-8d-cloud-metadata-design.md`

## Global Constraints

- No schema change: `osiris_schema::CloudContext { provider: String, instance_id: Option<String>, region: Option<String> }` and `HostRef.cloud: Option<CloudContext>` already exist.
- `provider` is always a constant set by the implementation: `"aws"`, `"azure"`, `"gcp"` — never taken from an IMDS response.
- `PROBE_TIMEOUT` = 1s per provider (whole provider flow, incl. AWS's two requests); `DETECT_TIMEOUT` = 2s wrapper in the Agent so boot is never blocked longer.
- Every provider failure (timeout, connection refused, non-2xx, malformed JSON, no usable field) yields `None` with `tracing::debug!`; never an error to the caller, never a startup failure.
- IMDS values are untrusted: each string field is trimmed, rejected (field → `None`) if it contains a control character, truncated to `MAX_FIELD_LEN` = 128 chars.
- HTTP clients for IMDS use `.no_proxy()` (metadata endpoints must never go through a proxy).
- Startup-only probe: no periodic re-probe, no tags/labels, no cloud credentials beyond the IMDSv2 session token.
- Base URLs: AWS/Azure `http://169.254.169.254`, GCP `http://metadata.google.internal`; overridable via `agent.yaml` `cloud_metadata` (tests and metadata proxies, not auto-discovery).
- Adding a field to `AgentConfig` breaks every struct-literal construction site: find them ALL with `grep -rn "AgentConfig {" crates` (currently `crates/osiris-agent/src/agent.rs` and 8 in `crates/osiris-e2e-tests/tests/end_to_end.rs`) and update each, then build the whole workspace.
- Before trusting `cargo test --workspace` after any change touching `osiris-agent`/`osiris-cli`/`osiris-server`, run `cargo build -p osiris-cli -p osiris-server -p osiris-agent` (e2e tests invoke prebuilt binaries).
- Commit messages end with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`. Use model `sonnet` for subagent dispatches (haiku is org-blocked).

---

### Task 1: `osiris-cloud-context` crate core (trait, sanitize, detect)

**Files:**
- Create: `crates/osiris-cloud-context/Cargo.toml`
- Create: `crates/osiris-cloud-context/src/lib.rs`
- Create: `crates/osiris-cloud-context/src/test_util.rs`
- (workspace `members = ["crates/*", ...]` already globs the new crate; no root Cargo.toml edit)

**Interfaces:**
- Produces (used by Tasks 2–4):
  - `pub trait CloudMetadataProvider: Send + Sync { async fn probe(&self) -> Option<CloudContext>; }` (`#[async_trait]`)
  - `pub const PROBE_TIMEOUT: Duration`, `pub const MAX_FIELD_LEN: usize`
  - `pub fn sanitize(raw: &str) -> Option<String>`
  - `pub(crate) fn http_client() -> reqwest::Client`
  - `pub async fn detect(providers: Vec<Box<dyn CloudMetadataProvider>>) -> Option<CloudContext>`
  - `#[cfg(test)] pub(crate) async fn test_util::serve(router: axum::Router) -> String` (returns `http://127.0.0.1:<port>`)

- [ ] **Step 1: Create the crate manifest**

```toml
[package]
name = "osiris-cloud-context"
version.workspace = true
edition.workspace = true

[dependencies]
async-trait = { workspace = true }
futures-util = { workspace = true }
reqwest = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
osiris-schema = { path = "../osiris-schema" }

[dev-dependencies]
axum = { workspace = true }
```

- [ ] **Step 2: Write the failing tests** — create `src/test_util.rs`:

```rust
use axum::Router;

/// Binds a mock metadata server on an ephemeral loopback port and returns
/// its base URL (`http://127.0.0.1:<port>`).
pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}
```

Create `src/lib.rs` with only the module wiring and tests first:

```rust
use std::time::Duration;

use async_trait::async_trait;
use osiris_schema::CloudContext;

#[cfg(test)]
pub(crate) mod test_util;

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Option<CloudContext>);
    #[async_trait]
    impl CloudMetadataProvider for Fixed {
        async fn probe(&self) -> Option<CloudContext> {
            self.0.clone()
        }
    }

    struct Slow;
    #[async_trait]
    impl CloudMetadataProvider for Slow {
        async fn probe(&self) -> Option<CloudContext> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(ctx("slow"))
        }
    }

    fn ctx(provider: &str) -> CloudContext {
        CloudContext { provider: provider.to_string(), instance_id: Some("i-1".into()), region: None }
    }

    #[test]
    fn sanitize_trims_and_keeps_normal_values() {
        assert_eq!(sanitize("  i-0abc\n").as_deref(), Some("i-0abc"));
    }

    #[test]
    fn sanitize_rejects_empty_and_control_characters() {
        assert_eq!(sanitize("   "), None);
        assert_eq!(sanitize("a\u{0007}b"), None);
        assert_eq!(sanitize("a\nb"), None, "an embedded newline is a control char");
    }

    #[test]
    fn sanitize_truncates_to_max_field_len() {
        let long = "x".repeat(MAX_FIELD_LEN + 50);
        assert_eq!(sanitize(&long).unwrap().chars().count(), MAX_FIELD_LEN);
    }

    #[tokio::test]
    async fn detect_returns_none_when_no_provider_answers() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> = vec![Box::new(Fixed(None)), Box::new(Fixed(None))];
        assert!(detect(providers).await.is_none());
        assert!(detect(vec![]).await.is_none());
    }

    #[tokio::test]
    async fn detect_returns_the_responding_provider() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Fixed(None)), Box::new(Fixed(Some(ctx("gcp"))))];
        assert_eq!(detect(providers).await.unwrap().provider, "gcp");
    }

    #[tokio::test]
    async fn detect_prefers_list_order_when_several_answer() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> =
            vec![Box::new(Fixed(Some(ctx("aws")))), Box::new(Fixed(Some(ctx("gcp"))))];
        assert_eq!(detect(providers).await.unwrap().provider, "aws");
    }

    #[tokio::test]
    async fn a_slow_provider_is_cut_off_at_probe_timeout() {
        let providers: Vec<Box<dyn CloudMetadataProvider>> = vec![Box::new(Slow), Box::new(Fixed(Some(ctx("azure"))))];
        let started = std::time::Instant::now();
        let got = detect(providers).await;
        assert_eq!(got.unwrap().provider, "azure");
        assert!(started.elapsed() < PROBE_TIMEOUT + Duration::from_secs(2), "slow provider must not stall detect");
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p osiris-cloud-context`
Expected: compile FAIL (`CloudMetadataProvider`, `sanitize`, `detect`, `MAX_FIELD_LEN`, `PROBE_TIMEOUT` not defined).

- [ ] **Step 4: Implement** — insert above the `#[cfg(test)]` items in `src/lib.rs`:

```rust
//! Optional Cloud context enrichment (ARCHITECTURE.md §21.4). Probes the
//! instance metadata service once at Agent startup; any failure leaves
//! `HostRef.cloud` as `None`, never a startup failure.

mod aws;
mod azure;
mod gcp;

pub use aws::AwsImdsV2;
pub use azure::AzureImds;
pub use gcp::GcpMetadata;

/// Per-provider budget for the whole probe flow (AWS's two requests share it).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest string field kept from an (untrusted) metadata response.
pub const MAX_FIELD_LEN: usize = 128;

#[async_trait]
pub trait CloudMetadataProvider: Send + Sync {
    /// `Some` only if this provider's metadata service answered with at
    /// least one usable field.
    async fn probe(&self) -> Option<CloudContext>;
}

/// Trims, rejects control characters (→ `None`), truncates to `MAX_FIELD_LEN`.
pub fn sanitize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(trimmed.chars().take(MAX_FIELD_LEN).collect())
}

/// IMDS must never go through an HTTP proxy, and must fail fast.
pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .no_proxy()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Probes every provider concurrently, each under `PROBE_TIMEOUT`, and
/// returns the first `Some` in list order (deterministic when several answer).
pub async fn detect(providers: Vec<Box<dyn CloudMetadataProvider>>) -> Option<CloudContext> {
    let probes = providers
        .iter()
        .map(|p| async move { tokio::time::timeout(PROBE_TIMEOUT, p.probe()).await.ok().flatten() });
    futures_util::future::join_all(probes).await.into_iter().flatten().next()
}
```

Create the three provider modules as stubs so the crate compiles (Tasks 2–3 fill them):

`src/aws.rs`, `src/azure.rs`, `src/gcp.rs` each: 

```rust
// filled in by its own task
pub struct AwsImdsV2; // (AzureImds / GcpMetadata respectively)
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p osiris-cloud-context`
Expected: 7 tests PASS (a `dead_code`/unused warning for stubs is fine).

- [ ] **Step 6: Commit**

```bash
git add crates/osiris-cloud-context Cargo.lock
git commit -m "feat(cloud): add osiris-cloud-context crate core (trait, sanitize, detect)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: AWS IMDSv2 provider

**Files:**
- Modify (replace stub): `crates/osiris-cloud-context/src/aws.rs`

**Interfaces:**
- Consumes (Task 1): `CloudMetadataProvider`, `sanitize`, `http_client`, `test_util::serve`.
- Produces: `pub struct AwsImdsV2` with `pub fn new() -> Self` (base `http://169.254.169.254`), `pub fn with_base_url(base: impl Into<String>) -> Self`, and `impl CloudMetadataProvider` returning `provider: "aws"`.

- [ ] **Step 1: Write the failing tests** — `src/aws.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::serve;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, put};
    use axum::Router;

    async fn token(headers: HeaderMap) -> impl IntoResponse {
        if headers.contains_key("x-aws-ec2-metadata-token-ttl-seconds") {
            (StatusCode::OK, "tok-123").into_response()
        } else {
            StatusCode::BAD_REQUEST.into_response()
        }
    }

    async fn doc(headers: HeaderMap) -> impl IntoResponse {
        let ok = headers.get("x-aws-ec2-metadata-token").and_then(|v| v.to_str().ok()) == Some("tok-123");
        if ok {
            (StatusCode::OK, r#"{"instanceId":"i-0abc","region":"us-east-1"}"#).into_response()
        } else {
            StatusCode::UNAUTHORIZED.into_response()
        }
    }

    fn happy() -> Router {
        Router::new()
            .route("/latest/api/token", put(token))
            .route("/latest/dynamic/instance-identity/document", get(doc))
    }

    #[tokio::test]
    async fn probes_a_v2_metadata_service() {
        let base = serve(happy()).await;
        let got = AwsImdsV2::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.provider, "aws");
        assert_eq!(got.instance_id.as_deref(), Some("i-0abc"));
        assert_eq!(got.region.as_deref(), Some("us-east-1"));
    }

    #[tokio::test]
    async fn token_step_failing_yields_none() {
        let router = Router::new().route("/latest/api/token", put(|| async { StatusCode::FORBIDDEN }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn document_404_yields_none() {
        let router = Router::new().route("/latest/api/token", put(|| async { "tok-123" }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn malformed_json_yields_none() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route("/latest/dynamic/instance-identity/document", get(|| async { "not json" }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn control_char_field_is_dropped_but_other_field_survives() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route(
                "/latest/dynamic/instance-identity/document",
                get(|| async { r#"{"instanceId":"i-bad","region":"eu-west-1"}"# }),
            );
        let base = serve(router).await;
        let got = AwsImdsV2::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.instance_id, None);
        assert_eq!(got.region.as_deref(), Some("eu-west-1"));
    }

    #[tokio::test]
    async fn no_usable_field_yields_none() {
        let router = Router::new()
            .route("/latest/api/token", put(|| async { "tok-123" }))
            .route("/latest/dynamic/instance-identity/document", get(|| async { "{}" }));
        let base = serve(router).await;
        assert!(AwsImdsV2::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        // Port 1 on loopback: connection refused.
        assert!(AwsImdsV2::with_base_url("http://127.0.0.1:1").probe().await.is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p osiris-cloud-context aws`
Expected: FAIL (`with_base_url`/`probe` not defined on the stub).

- [ ] **Step 3: Implement** — put above the test module in `src/aws.rs` (replacing the stub struct):

```rust
use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://169.254.169.254";

/// AWS EC2 Instance Metadata Service, v2 (session-token) only.
pub struct AwsImdsV2 {
    base: String,
    client: reqwest::Client,
}

impl AwsImdsV2 {
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE)
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        Self { base: base.into().trim_end_matches('/').to_string(), client: http_client() }
    }

    async fn try_probe(&self) -> Result<Option<CloudContext>, reqwest::Error> {
        let token = self
            .client
            .put(format!("{}/latest/api/token", self.base))
            .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let body = self
            .client
            .get(format!("{}/latest/dynamic/instance-identity/document", self.base))
            .header("X-aws-ec2-metadata-token", token.trim())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
            return Ok(None);
        };
        let field = |k: &str| doc.get(k).and_then(|v| v.as_str()).and_then(sanitize);
        let (instance_id, region) = (field("instanceId"), field("region"));
        if instance_id.is_none() && region.is_none() {
            return Ok(None);
        }
        Ok(Some(CloudContext { provider: "aws".to_string(), instance_id, region }))
    }
}

impl Default for AwsImdsV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudMetadataProvider for AwsImdsV2 {
    async fn probe(&self) -> Option<CloudContext> {
        match self.try_probe().await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::debug!(error = %e, "aws imds probe failed");
                None
            }
        }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p osiris-cloud-context`
Expected: all PASS (Task 1's 7 + 7 new).

- [ ] **Step 5: Commit**

```bash
git add crates/osiris-cloud-context
git commit -m "feat(cloud): add AWS IMDSv2 provider

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Azure IMDS and GCP metadata providers

**Files:**
- Modify (replace stubs): `crates/osiris-cloud-context/src/azure.rs`, `crates/osiris-cloud-context/src/gcp.rs`

**Interfaces:**
- Consumes (Task 1): `CloudMetadataProvider`, `sanitize`, `http_client`, `test_util::serve`.
- Produces: `AzureImds` (`new()` base `http://169.254.169.254`, `with_base_url`, provider `"azure"`) and `GcpMetadata` (`new()` base `http://metadata.google.internal`, `with_base_url`, provider `"gcp"`); both `impl CloudMetadataProvider`. Also `pub(crate) fn gcp_region_from_zone(zone: &str) -> Option<String>` in `gcp.rs`.

- [ ] **Step 1: Write the failing Azure tests** — `src/azure.rs`:

```rust
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
            (StatusCode::OK, r#"{"compute":{"vmId":"vm-42","location":"westeurope"}}"#).into_response()
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
        let base = serve(Router::new().route("/metadata/instance", get(|| async { "<html>" }))).await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn missing_compute_object_yields_none() {
        let base = serve(Router::new().route("/metadata/instance", get(|| async { r#"{"network":{}}"# }))).await;
        assert!(AzureImds::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        assert!(AzureImds::with_base_url("http://127.0.0.1:1").probe().await.is_none());
    }
}
```

- [ ] **Step 2: Write the failing GCP tests** — `src/gcp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::serve;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    fn flavored(headers: &HeaderMap) -> bool {
        headers.get("metadata-flavor").and_then(|v| v.to_str().ok()) == Some("Google")
    }

    async fn id(headers: HeaderMap) -> impl IntoResponse {
        if flavored(&headers) { (StatusCode::OK, "1234567890\n").into_response() } else { StatusCode::FORBIDDEN.into_response() }
    }

    async fn zone(headers: HeaderMap) -> impl IntoResponse {
        if flavored(&headers) {
            (StatusCode::OK, "projects/123/zones/us-central1-a").into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        }
    }

    #[test]
    fn zone_maps_to_region() {
        assert_eq!(gcp_region_from_zone("projects/123/zones/us-central1-a").as_deref(), Some("us-central1"));
        assert_eq!(gcp_region_from_zone("europe-west4-b").as_deref(), Some("europe-west4"));
        assert_eq!(gcp_region_from_zone("weird").as_deref(), Some("weird"));
        assert_eq!(gcp_region_from_zone(""), None);
    }

    #[tokio::test]
    async fn probes_gcp_metadata_sending_the_required_header() {
        let router = Router::new()
            .route("/computeMetadata/v1/instance/id", get(id))
            .route("/computeMetadata/v1/instance/zone", get(zone));
        let base = serve(router).await;
        let got = GcpMetadata::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.provider, "gcp");
        assert_eq!(got.instance_id.as_deref(), Some("1234567890"), "trailing newline trimmed");
        assert_eq!(got.region.as_deref(), Some("us-central1"));
    }

    #[tokio::test]
    async fn id_endpoint_missing_yields_none() {
        let base = serve(Router::new()).await;
        assert!(GcpMetadata::with_base_url(base).probe().await.is_none());
    }

    #[tokio::test]
    async fn zone_failure_still_returns_the_instance_id() {
        let router = Router::new().route("/computeMetadata/v1/instance/id", get(id));
        let base = serve(router).await;
        let got = GcpMetadata::with_base_url(base).probe().await.unwrap();
        assert_eq!(got.instance_id.as_deref(), Some("1234567890"));
        assert_eq!(got.region, None);
    }

    #[tokio::test]
    async fn unreachable_endpoint_yields_none() {
        assert!(GcpMetadata::with_base_url("http://127.0.0.1:1").probe().await.is_none());
    }
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p osiris-cloud-context azure gcp`
Expected: FAIL (methods not defined on stubs).

- [ ] **Step 4: Implement Azure** — above the tests in `src/azure.rs`:

```rust
use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://169.254.169.254";

/// Azure Instance Metadata Service.
pub struct AzureImds {
    base: String,
    client: reqwest::Client,
}

impl AzureImds {
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE)
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        Self { base: base.into().trim_end_matches('/').to_string(), client: http_client() }
    }

    async fn try_probe(&self) -> Result<Option<CloudContext>, reqwest::Error> {
        let body = self
            .client
            .get(format!("{}/metadata/instance?api-version=2021-02-01", self.base))
            .header("Metadata", "true")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
            return Ok(None);
        };
        let Some(compute) = doc.get("compute") else {
            return Ok(None);
        };
        let field = |k: &str| compute.get(k).and_then(|v| v.as_str()).and_then(sanitize);
        let (instance_id, region) = (field("vmId"), field("location"));
        if instance_id.is_none() && region.is_none() {
            return Ok(None);
        }
        Ok(Some(CloudContext { provider: "azure".to_string(), instance_id, region }))
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
```

- [ ] **Step 5: Implement GCP** — above the tests in `src/gcp.rs`:

```rust
use async_trait::async_trait;
use osiris_schema::CloudContext;

use crate::{http_client, sanitize, CloudMetadataProvider};

const DEFAULT_BASE: &str = "http://metadata.google.internal";

/// GCP Compute Engine metadata server.
pub struct GcpMetadata {
    base: String,
    client: reqwest::Client,
}

/// `projects/<n>/zones/us-central1-a` (or a bare zone) → `us-central1`.
pub(crate) fn gcp_region_from_zone(zone: &str) -> Option<String> {
    let segment = zone.trim().rsplit('/').next().unwrap_or("");
    if segment.is_empty() {
        return None;
    }
    Some(segment.rsplit_once('-').map(|(region, _)| region).unwrap_or(segment).to_string())
}

impl GcpMetadata {
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE)
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        Self { base: base.into().trim_end_matches('/').to_string(), client: http_client() }
    }

    async fn get_text(&self, path: &str) -> Result<String, reqwest::Error> {
        self.client
            .get(format!("{}/computeMetadata/v1/instance/{path}", self.base))
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }

    async fn try_probe(&self) -> Result<Option<CloudContext>, reqwest::Error> {
        let instance_id = sanitize(&self.get_text("id").await?);
        // A zone failure must not discard an otherwise-valid instance id.
        let region = match self.get_text("zone").await {
            Ok(zone) => gcp_region_from_zone(&zone).as_deref().and_then(sanitize),
            Err(e) => {
                tracing::debug!(error = %e, "gcp zone lookup failed");
                None
            }
        };
        if instance_id.is_none() && region.is_none() {
            return Ok(None);
        }
        Ok(Some(CloudContext { provider: "gcp".to_string(), instance_id, region }))
    }
}

impl Default for GcpMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudMetadataProvider for GcpMetadata {
    async fn probe(&self) -> Option<CloudContext> {
        match self.try_probe().await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::debug!(error = %e, "gcp metadata probe failed");
                None
            }
        }
    }
}
```

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p osiris-cloud-context`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/osiris-cloud-context
git commit -m "feat(cloud): add Azure IMDS and GCP metadata providers

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Agent config + startup wiring

**Files:**
- Modify: `crates/osiris-agent/Cargo.toml` (add dependency)
- Modify: `crates/osiris-agent/src/config.rs` (new `CloudMetadataConfig`, new `AgentConfig.cloud_metadata` field)
- Create: `crates/osiris-agent/src/cloud.rs`
- Modify: `crates/osiris-agent/src/lib.rs` (`pub mod cloud;`)
- Modify: `crates/osiris-agent/src/main.rs` (use the probe result)
- Modify: every `AgentConfig { ... }` struct literal (`grep -rn "AgentConfig {" crates`): `crates/osiris-agent/src/agent.rs` (`base_config`) and all 8 in `crates/osiris-e2e-tests/tests/end_to_end.rs` — add `cloud_metadata: Default::default(),`. In e2e tests, set `enabled: false` is NOT needed if the default is fine, but a real probe against 169.254.169.254 would slow those tests, so use `cloud_metadata: osiris_agent::config::CloudMetadataConfig { enabled: false, ..Default::default() },` there (check how the e2e file imports `AgentConfig`; `Agent::start` does not call the probe, only `main.rs` does — so `Default::default()` is also acceptable; prefer `Default::default()` for minimal diff and note that `Agent::start` never probes).

**Interfaces:**
- Consumes (Tasks 1–3): `osiris_cloud_context::{detect, AwsImdsV2, AzureImds, GcpMetadata, CloudMetadataProvider}`.
- Produces:
  - `pub struct CloudMetadataConfig { pub enabled: bool, pub aws_base_url: Option<String>, pub azure_base_url: Option<String>, pub gcp_base_url: Option<String> }` (`Deserialize`, `Clone`, `Debug`, `Default` with `enabled: true`), in `config.rs`
  - `AgentConfig.cloud_metadata: CloudMetadataConfig` (`#[serde(default)]`)
  - `pub fn build_providers(cfg: &CloudMetadataConfig) -> Vec<Box<dyn CloudMetadataProvider>>` and `pub async fn detect_cloud_context(cfg: &CloudMetadataConfig) -> Option<osiris_schema::CloudContext>` in `cloud.rs`
  - `pub const DETECT_TIMEOUT: Duration` (2s)

- [ ] **Step 1: Add dependency** — in `crates/osiris-agent/Cargo.toml` `[dependencies]`:

```toml
osiris-cloud-context = { path = "../osiris-cloud-context" }
```

Under `[dev-dependencies]` nothing new is needed (`axum`, `tokio` are already normal dependencies).

- [ ] **Step 2: Write the failing config tests** — append to the `tests` module in `crates/osiris-agent/src/config.rs`:

```rust
    #[test]
    fn cloud_metadata_defaults_to_enabled_with_no_overrides_so_old_configs_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\n").unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(config.cloud_metadata.enabled);
        assert!(config.cloud_metadata.aws_base_url.is_none());
    }

    #[test]
    fn cloud_metadata_section_parses_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(
            &path,
            "spool_path: /tmp/s.ndjson\nstatus_addr: 127.0.0.1:9200\ncloud_metadata:\n  enabled: false\n  gcp_base_url: http://127.0.0.1:9\n",
        )
        .unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert!(!config.cloud_metadata.enabled);
        assert_eq!(config.cloud_metadata.gcp_base_url.as_deref(), Some("http://127.0.0.1:9"));
    }
```

- [ ] **Step 3: Write the failing cloud helper tests** — create `crates/osiris-agent/src/cloud.rs` with tests only first:

```rust
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
        let cfg = CloudMetadataConfig { enabled: false, ..Default::default() };
        assert!(build_providers(&cfg).is_empty());
    }

    #[test]
    fn enabled_builds_three_providers() {
        assert_eq!(build_providers(&CloudMetadataConfig::default()).len(), 3);
    }

    #[tokio::test]
    async fn disabled_skips_probing_entirely() {
        let cfg = CloudMetadataConfig { enabled: false, ..none_reachable() };
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
        let cfg = CloudMetadataConfig { aws_base_url: Some(base), ..none_reachable() };
        let got = detect_cloud_context(&cfg).await.unwrap();
        assert_eq!(got.provider, "aws");
        assert_eq!(got.instance_id.as_deref(), Some("i-9"));
    }
}
```

Add `pub mod cloud;` to `crates/osiris-agent/src/lib.rs` (after `pub mod agent;`).

- [ ] **Step 4: Run to verify they fail**

Run: `cargo test -p osiris-agent cloud`
Expected: compile FAIL (`CloudMetadataConfig`, `build_providers`, `detect_cloud_context` not defined).

- [ ] **Step 5: Implement config** — in `crates/osiris-agent/src/config.rs`, above `AgentConfig`:

```rust
/// Optional Cloud metadata probe config (ARCHITECTURE.md §21.4). On by
/// default; the per-provider base URLs exist for tests and proxied
/// metadata services — they are not auto-discovery.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudMetadataConfig {
    #[serde(default = "default_cloud_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub aws_base_url: Option<String>,
    #[serde(default)]
    pub azure_base_url: Option<String>,
    #[serde(default)]
    pub gcp_base_url: Option<String>,
}

fn default_cloud_enabled() -> bool {
    true
}

impl Default for CloudMetadataConfig {
    fn default() -> Self {
        Self { enabled: true, aws_base_url: None, azure_base_url: None, gcp_base_url: None }
    }
}
```

and inside `AgentConfig` (before `spool_path`):

```rust
    /// Cloud metadata probe (Phase 8d). Defaults to enabled, no overrides,
    /// so every pre-8d agent.yaml still loads.
    #[serde(default)]
    pub cloud_metadata: CloudMetadataConfig,
```

Export it: in `lib.rs` change `pub use config::AgentConfig;` to `pub use config::{AgentConfig, CloudMetadataConfig};`.

- [ ] **Step 6: Implement the helper** — above the tests in `src/cloud.rs`:

```rust
use std::time::Duration;

use osiris_cloud_context::{detect, AwsImdsV2, AzureImds, CloudMetadataProvider, GcpMetadata};
use osiris_schema::CloudContext;

use crate::config::CloudMetadataConfig;

/// Outer bound on the whole startup probe so boot is never blocked longer.
pub const DETECT_TIMEOUT: Duration = Duration::from_secs(2);

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
    vec![Box::new(aws), Box::new(azure), Box::new(gcp)]
}

/// `None` when disabled, on-prem/bare-metal, or the probe times out —
/// never a startup failure.
pub async fn detect_cloud_context(cfg: &CloudMetadataConfig) -> Option<CloudContext> {
    let providers = build_providers(cfg);
    if providers.is_empty() {
        return None;
    }
    tokio::time::timeout(DETECT_TIMEOUT, detect(providers)).await.ok().flatten()
}
```

- [ ] **Step 7: Wire `main.rs`** — replace `cloud: None,` and the `let host = HostRef { ... }` block so the probe runs before it:

```rust
    let cloud = osiris_agent::cloud::detect_cloud_context(&config.cloud_metadata).await;
    match &cloud {
        Some(c) => tracing::info!(provider = %c.provider, "cloud metadata detected"),
        None => tracing::debug!("no cloud metadata detected (on-prem, disabled, or unreachable)"),
    }
    let host = HostRef {
        host_id,
        hostname,
        distro: "unknown".to_string(),
        kernel_version: "unknown".to_string(),
        cloud,
    };
```

- [ ] **Step 8: Update every `AgentConfig` struct literal** — run `grep -rn "AgentConfig {" crates`; in each literal add `cloud_metadata: Default::default(),` (after `proc_root`/`synthetic_scenario` — order is irrelevant). Do not touch `pub struct AgentConfig {` itself.

- [ ] **Step 9: Run tests and workspace build**

Run: `cargo test -p osiris-agent` → all PASS (new: 2 config + 5 cloud).
Run: `cargo build --workspace --tests` → no errors (proves no literal site was missed).

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-agent crates/osiris-e2e-tests Cargo.lock
git commit -m "feat(agent): probe cloud metadata at startup and populate HostRef.cloud

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: `/api/v1/hosts` cloud fields + Console column

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (`HostSummary` ~line 674, `build_host_rows` ~line 732, tests module)
- Modify: `console/src/api/types.ts` (`HostSummary`)
- Modify: `console/src/screens/hosts/HostList.tsx`
- Modify: `console/src/screens/hosts/HostList.test.tsx`

**Interfaces:**
- Consumes: `osiris_schema::CloudContext` (re-exported from `osiris_schema` root via `pub use entities::*`), `HostRef.cloud` on the latest event.
- Produces: JSON fields `cloud_provider`, `cloud_instance_id`, `cloud_region` (each string or `null`) on every `/api/v1/hosts` row; TS `HostSummary` gains the same three as optional nullable fields.

- [ ] **Step 1: Write the failing backend tests** — add to the tests module in `crates/osiris-api/src/lib.rs`, next to the other `build_host_rows_*` tests:

```rust
    #[test]
    fn build_host_rows_carries_cloud_fields_from_the_latest_event() {
        let now = now_ns_for_test();
        let host_a = uuid::Uuid::new_v4();
        let mut old = host_event(host_a, "h", now - 20 * 1_000_000_000);
        old.host.cloud = Some(osiris_schema::CloudContext {
            provider: "gcp".to_string(),
            instance_id: Some("old-id".to_string()),
            region: None,
        });
        let mut latest = host_event(host_a, "h", now - 5 * 1_000_000_000);
        latest.host.cloud = Some(osiris_schema::CloudContext {
            provider: "aws".to_string(),
            instance_id: Some("i-0abc".to_string()),
            region: Some("us-east-1".to_string()),
        });

        let rows = build_host_rows(vec![old, latest], now, false);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cloud_provider.as_deref(), Some("aws"));
        assert_eq!(rows[0].cloud_instance_id.as_deref(), Some("i-0abc"));
        assert_eq!(rows[0].cloud_region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn build_host_rows_cloud_fields_are_none_and_serialize_as_null_when_absent() {
        let now = now_ns_for_test();
        let rows = build_host_rows(vec![host_event(uuid::Uuid::new_v4(), "h", now - 1_000_000_000)], now, false);
        assert!(rows[0].cloud_provider.is_none());
        let json = serde_json::to_value(&rows[0]).unwrap();
        assert!(json["cloud_provider"].is_null());
        assert!(json["cloud_instance_id"].is_null());
        assert!(json["cloud_region"].is_null());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p osiris-api build_host_rows`
Expected: compile FAIL (no `cloud_provider` field on `HostSummary`).

- [ ] **Step 3: Implement backend** — add to `HostSummary` (after `status`):

```rust
    cloud_provider: Option<String>,
    cloud_instance_id: Option<String>,
    cloud_region: Option<String>,
```

and in `build_host_rows`'s `.map(|event| { ... })`, before constructing the `HostSummary`:

```rust
            let (cloud_provider, cloud_instance_id, cloud_region) = match event.host.cloud {
                Some(c) => (Some(c.provider), c.instance_id, c.region),
                None => (None, None, None),
            };
```

then add `cloud_provider, cloud_instance_id, cloud_region,` to the `HostSummary { ... }` literal. (`event.host.hostname` etc. are already moved field-by-field there; moving `event.host.cloud` alongside is the same pattern.) Update the handler's doc comment with one line: "Cloud fields come from the latest event's `host.cloud` (Phase 8d); absent → null."

Grep `HostSummary {` in `crates/osiris-api` for any other literal construction and update it.

- [ ] **Step 4: Run backend tests**

Run: `cargo test -p osiris-api`
Expected: all PASS (existing 114+6 plus 2 new).

- [ ] **Step 5: Write the failing Console test** — append inside the `describe("HostList", ...)` block in `HostList.test.tsx`:

```tsx
  it("renders a Cloud column with provider and region, and a dash when absent", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "cloud-host", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 1000, status: "ONLINE", cloud_provider: "aws", cloud_instance_id: "i-0abc", cloud_region: "us-east-1" },
          { host_id: "22222222-2222-2222-2222-222222222222", hostname: "onprem-host", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 900, status: "STALE", cloud_provider: null, cloud_instance_id: null, cloud_region: null },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByRole("columnheader", { name: "Cloud" })).toBeInTheDocument();
    expect(screen.getByText("aws / us-east-1")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });
```

- [ ] **Step 6: Run to verify it fails**

Run (from `console/`): `npx vitest run src/screens/hosts/HostList.test.tsx`
Expected: FAIL (no "Cloud" column header).

- [ ] **Step 7: Implement Console** — `types.ts` `HostSummary` gains (after `status`):

```ts
  cloud_provider?: string | null;
  cloud_instance_id?: string | null;
  cloud_region?: string | null;
```

`HostList.tsx`: add `<th>Cloud</th>` after the Status header, and after the status cell:

```tsx
                <td>{formatCloud(row)}</td>
```

with a module-level helper above `HostList`:

```tsx
// Phase 8d: provider (+ region when known) from the host's cloud metadata
// probe, or a dash for on-prem/bare-metal hosts (cloud is null there).
function formatCloud(row: HostSummary): string {
  if (!row.cloud_provider) return "—";
  return row.cloud_region ? `${row.cloud_provider} / ${row.cloud_region}` : row.cloud_provider;
}
```

and `import type { HostSummary } from "../../api/types";` at the top.

- [ ] **Step 8: Run Console tests and build**

Run (from `console/`): `npx vitest run` → all PASS (218 existing + 1 new).
Run: `npm run build` → tsc + vite clean.

- [ ] **Step 9: Full verification**

Run: `cargo build -p osiris-cli -p osiris-server -p osiris-agent` then `cargo test --workspace` → all green.

- [ ] **Step 10: Commit**

```bash
git add crates/osiris-api console/src
git commit -m "feat(hosts): surface cloud provider/instance/region in the Host Registry

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** §3 crate/trait/providers/`detect`/reqwest+timeouts → Tasks 1–3; §2 provider constants → Tasks 2–3; §4 Agent startup + `DETECT_TIMEOUT` + config section + overrides → Task 4; §4 API fields + Console column → Task 5; §5 error handling (all failures → `None`, sanitization, constant `provider`) → Tasks 1–3 (`sanitize`, tests for malformed/404/timeout/control-char); §6 test list: per-provider success/missing-header/404/timeout(`Slow` in Task 1, unreachable in 2–3)/malformed/sanitization ✓, AWS token-step ✓, `detect` cases ✓, agent override wiring + `enabled:false` ✓, API cloud/null ✓, Console column ✓; §7 Non-Goals honored (no re-probe, tags, schema change).

**Placeholders:** none; every code step has code. The only "find them all" instruction (Task 4 Step 8) gives the exact grep and known count.

**Type consistency:** `CloudMetadataProvider::probe`, `with_base_url`, `sanitize`, `http_client`, `serve`, `detect`, `build_providers`, `detect_cloud_context`, `CloudMetadataConfig` fields, and `cloud_provider`/`cloud_instance_id`/`cloud_region` are spelled identically across tasks. Note for executors: `test_util::serve` is `pub(crate)` in `osiris-cloud-context`, so the Agent crate's tests carry their own tiny `serve` (Task 4 Step 3) rather than importing it.
