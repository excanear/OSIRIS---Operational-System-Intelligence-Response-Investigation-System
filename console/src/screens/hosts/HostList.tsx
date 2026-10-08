import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useHosts } from "../../api/hooks";
import type { HostSummary } from "../../api/types";
import { HostPolicyPanel } from "./HostPolicyPanel";

// GET /api/v1/hosts (hosts_handler in crates/osiris-api/src/fleet.rs, Phase
// 9d-1) reads the real fleet registry (osiris-fleet's HostRegistry) instead
// of scanning recent events: one row per host that has sent at least one
// AGENT_HEALTH heartbeat, with `status` derived from how recent that host's
// `last_seen` heartbeat is relative to the `EXPECTED_HEARTBEAT_INTERVAL_NS`
// constant defined in that module. Phase 9d-2: each row also carries its
// host groups, and the list can be filtered to a single group via `?group=`.

// Phase 8d: provider (+ region when known) from the host's cloud metadata
// probe, or a dash for on-prem/bare-metal hosts (cloud is null there).
function formatCloud(row: HostSummary): string {
  if (!row.cloud_provider) return "—";
  return row.cloud_region ? `${row.cloud_provider} / ${row.cloud_region}` : row.cloud_provider;
}

export function HostList() {
  const [params] = useSearchParams();
  const groupFilter = params.get("group") ?? undefined;
  const hosts = useHosts(groupFilter);
  const rows = hosts.data ?? [];
  const [policyHost, setPolicyHost] = useState<string | null>(null);
  const filterName = groupFilter
    ? (rows.flatMap((r) => r.groups).find((g) => g.group_id === groupFilter)?.name ?? groupFilter)
    : undefined;

  return (
    <div>
      <h1>Hosts</h1>
      {groupFilter && (
        <p>
          Filtered by group {filterName} <Link to="/hosts">Clear filter</Link>
        </p>
      )}
      {hosts.isLoading && <p>Loading hosts…</p>}
      {hosts.isError && (
        <p role="alert">Failed to load hosts: {(hosts.error as Error).message}</p>
      )}
      {!hosts.isLoading && !hosts.isError && rows.length === 0 && <p>No hosts found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Distro</th>
              <th>Kernel</th>
              <th>Agent version</th>
              <th>Enrolled</th>
              <th>Last Seen</th>
              <th>Status</th>
              <th>Cloud</th>
              <th>Groups</th>
              <th>Policy</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.host_id}>
                <td>
                  <Link to={`/timeline?host=${encodeURIComponent(row.host_id)}`}>{row.hostname}</Link>
                </td>
                <td>{row.distro}</td>
                <td>{row.kernel_version}</td>
                <td>{row.agent_version}</td>
                <td>{new Date(row.enrolled_at / 1_000_000).toLocaleString()}</td>
                <td>{new Date(row.last_seen / 1_000_000).toLocaleString()}</td>
                <td>{row.status}</td>
                <td>{formatCloud(row)}</td>
                <td>
                  {row.groups.map((g, i) => (
                    <span key={g.group_id}>
                      {i > 0 && ", "}
                      <Link to={`/groups/${encodeURIComponent(g.group_id)}`}>{g.name}</Link>
                    </span>
                  ))}
                </td>
                <td>
                  <button
                    type="button"
                    onClick={() => setPolicyHost(policyHost === row.host_id ? null : row.host_id)}
                  >
                    {row.policy_status}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {policyHost && <HostPolicyPanel hostId={policyHost} />}
    </div>
  );
}
