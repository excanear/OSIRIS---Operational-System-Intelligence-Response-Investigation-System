import { Link } from "react-router-dom";
import { useHosts } from "../../api/hooks";

// GET /api/v1/hosts (hosts_handler in crates/osiris-api/src/fleet.rs, Phase
// 9d-1) reads the real fleet registry (osiris-fleet's HostRegistry) instead
// of scanning recent events: one row per host that has sent at least one
// AGENT_HEALTH heartbeat, with `status` derived from how recent that host's
// `last_seen` heartbeat is relative to the `EXPECTED_HEARTBEAT_INTERVAL_NS`
// constant defined in that module.
export function HostList() {
  const hosts = useHosts();
  const rows = hosts.data ?? [];

  return (
    <div>
      <h1>Hosts</h1>
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
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
