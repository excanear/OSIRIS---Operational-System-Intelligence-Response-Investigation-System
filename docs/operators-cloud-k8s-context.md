# Operator guide — cloud and Kubernetes context (agent.yaml)

Both sections are optional; an `agent.yaml` without them keeps working.

## `cloud_metadata` (Phase 8d)

Detects AWS / Azure / GCP from the instance metadata service, once at agent start.

| key | default | meaning |
|---|---|---|
| `enabled` | `true` | Set `false` to skip probing entirely (no network calls). |
| `aws_base_url`, `azure_base_url`, `gcp_base_url` | unset | Override the metadata endpoint (tests, proxies). Not validated: only point them at a service you trust. |

Probes run concurrently, 1 s timeout each, never through an HTTP proxy. Values
containing control, bidirectional or zero-width characters are discarded. The
cloud fields come from the latest event, so an agent restarted while the
metadata service is unreachable shows `—` in the Console.

## `k8s_context` (Phase 8e)

Resolves container → pod (name, namespace) from the node's kubelet.

| key | default | meaning |
|---|---|---|
| `enabled` | `true` | Active only if `kubelet_url` is set or a service-account token exists; a non-Kubernetes host makes no connection. |
| `kubelet_url` | unset | e.g. `https://127.0.0.1:10250`. |
| `token_path` | service-account default | Bearer token file. Sent only over verified TLS (or to a loopback kubelet with `insecure_skip_verify`). Never sent over plain http. |
| `ca_path` | unset | CA bundle for the kubelet's certificate. |
| `insecure_skip_verify` | `false` | Disables TLS verification. A startup warning is logged; the token is withheld from non-loopback hosts. |
| `refresh_secs` | `30` | Pod-list refresh interval (floor of 5). |

### RBAC required

The agent's service account needs read access to the kubelet's pod list:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: osiris-agent-kubelet }
rules:
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get"]
```

Bind it to the agent's service account with a `ClusterRoleBinding`. Fetch
failures are logged at `warn` with a token-free cause (timeout, TLS, HTTP
status, parse).
