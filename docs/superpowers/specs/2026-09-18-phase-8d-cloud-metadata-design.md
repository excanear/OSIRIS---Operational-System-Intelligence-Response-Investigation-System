# Phase 8d: Cloud Metadata Probe — Design

Date: 2026-09-18. Status: approved in chat, pending written-spec review.
Source: ARCHITECTURE.md §21.4 (Cloud context), §9.2 (`HostRef.cloud`), §93 (Phase 8).

## 1. Scope and decomposition

Phase 8 was decomposed into 8a (RBAC/auth), 8b (Response Engine v1), 8c (Host Registry). The
remainder of §21 splits into:

- **8d (this phase): Cloud metadata probe** — populate `HostRef.cloud`.
- 8e: Kubernetes context (`osiris-k8s-context`, populates `ContainerRef.pod_ref`).
- 8f: multi-tenant `tenant_id` row-level scoping.

Chosen first because it is self-contained (one startup probe, no cluster needed) and testable
with a local mock HTTP server.

## 2. Schema

No schema change. `CloudContext { provider, instance_id, region }` and
`HostRef.cloud: Option<CloudContext>` already exist (`crates/osiris-schema/src/entities.rs`).
Today `osiris-agent/src/main.rs` hardcodes `cloud: None`. `provider` values: `"aws"`,
`"azure"`, `"gcp"`.

## 3. New crate `osiris-cloud-context`

One crate per subsystem, matching `osiris-auth` / `osiris-response`.

```rust
#[async_trait]
pub trait CloudMetadataProvider: Send + Sync {
    async fn probe(&self) -> Option<CloudContext>;
}
```

Implementations (each with `new()` using the well-known endpoint and `with_base_url()` for tests
and metadata proxies):

| Provider | Flow |
|---|---|
| `AwsImdsV2` | `PUT /latest/api/token` (header `X-aws-ec2-metadata-token-ttl-seconds`), then `GET /latest/dynamic/instance-identity/document` with `X-aws-ec2-metadata-token`; base `http://169.254.169.254` |
| `AzureImds` | `GET /metadata/instance?api-version=2021-02-01`, header `Metadata: true`; same base |
| `GcpMetadata` | `GET /computeMetadata/v1/instance/id` and `/zone`, header `Metadata-Flavor: Google`; base `http://metadata.google.internal` |

`detect(providers: Vec<Box<dyn CloudMetadataProvider>>) -> Option<CloudContext>` probes all
providers concurrently and returns the first `Some`. Nothing is assumed: an environment is
cloud only if a provider answers.

HTTP client: `reqwest` (already a workspace dependency; async client, per-request timeout
`PROBE_TIMEOUT` = 1s; the AWS two-step flow shares one timeout budget).

## 4. Integration

- **Agent** (`crates/osiris-agent/src/main.rs`): once at startup, before `Agent::start`,
  `cloud = detect(default_providers(&config)).await` wrapped in an overall timeout
  (`DETECT_TIMEOUT` = 2s) so boot is never blocked longer than that. The result replaces
  `cloud: None` in the `HostRef`; it then rides on every event automatically.
- **Config**: optional `cloud_metadata` section in `agent.yaml` (`enabled: bool` default true,
  optional per-provider `base_url` override). Overrides exist for tests and proxied metadata
  services; they are not auto-discovery.
- **API** (`hosts_handler` / `build_host_rows`): `HostSummary` gains
  `cloud_provider`, `cloud_instance_id`, `cloud_region` (all `Option<String>`, serialized as
  null when absent), read from the most-recent event's `host.cloud`. No new query or storage.
- **Console**: `HostSummary` TS type gains the three optional fields; `HostList` gains a
  "Cloud" column (`provider` + `region`, `—` when absent).

## 5. Error handling

Any failure in a provider (timeout, connection refused, non-2xx, malformed JSON, missing
fields) yields `None` with a `tracing::debug!`; never an error to the caller. If nothing
answers (on-prem / bare metal), `cloud` stays `None` and startup continues (§21.4).

Values returned by an IMDS are untrusted (an attacker controlling the network path or a
compromised proxy could forge them). Each string field is sanitized: truncated to 128 chars
and rejected (field becomes `None`) if it contains control characters. `provider` is always a
constant set by the implementation, never taken from the response.

## 6. Testing

- Per provider, against a local axum mock: success; required header missing → provider
  returns `None`; 404; timeout; malformed JSON; oversize/control-char field sanitization.
- AWS: token step failing → `None`; token sent on the second request.
- `detect`: picks the responding provider among several; all failing → `None`; slow provider
  does not delay past the timeout.
- Agent: config override wiring (unit test on the provider-construction helper); `enabled:
  false` skips probing.
- API: `build_host_rows` carries cloud fields from the latest event, and null when absent.
- Console: `HostList` renders the Cloud column with and without data.
- Full workspace and console suites green; rebuild `osiris-cli`/`osiris-server`/`osiris-agent`
  before trusting `osiris-e2e-tests`.

## 7. Non-Goals

Kubernetes context (8e); multi-tenant scoping (8f); periodic re-probe (startup only, per
§21.4); instance tags/labels; cloud credentials or any auth beyond the IMDSv2 session token;
changing `HostRef` schema; auto-discovery of proxied metadata endpoints.
