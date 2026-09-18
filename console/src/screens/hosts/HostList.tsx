import { Link } from "react-router-dom";
import { useHosts } from "../../api/hooks";
import type { HostSummary } from "../../api/types";

// Phase 8d: provider (+ region when known) from the host's cloud metadata
// probe, or a dash for on-prem/bare-metal hosts (cloud is null there).
function formatCloud(row: HostSummary): string {
  if (!row.cloud_provider) return "—";
  return row.cloud_region ? `${row.cloud_provider} / ${row.cloud_region}` : row.cloud_provider;
}

// GET /api/v1/hosts (hosts_handler in crates/osiris-api/src/lib.rs) queries
// a bounded, time-windowed event scan capped at MAX_EVENT_LIMIT (5,000)
// events, ordered oldest-first, breaking once the cap is hit. If that cap is
// hit, the handler cannot tell whether any given host's true most-recent
// event fell inside or outside the truncated portion of the window, so it
// reports `status: "UNKNOWN"` for EVERY row in the response rather than a
// possibly-wrong ONLINE/STALE verdict. "UNKNOWN" therefore means "liveness
// cannot currently be determined for any host in this response" (a
// query-wide condition), not "these specific hosts are unknown."
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
              <th>Last Seen</th>
              <th>Status</th>
              <th>Cloud</th>
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
                <td>{new Date(row.last_seen / 1_000_000).toLocaleString()}</td>
                <td>{row.status}</td>
                <td>{formatCloud(row)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
