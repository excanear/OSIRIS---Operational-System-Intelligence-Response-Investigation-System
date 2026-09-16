import { useState } from "react";
import { Link } from "react-router-dom";
import { useNetwork } from "../../api/hooks";

export function NetworkList() {
  // GET /api/v1/network (network_handler in crates/osiris-api/src/lib.rs)
  // dedups by (host_id, dst_ip, dst_port, proto) over a bounded
  // 10_000-event query window, unordered by recency (query_events has no
  // ORDER BY timestamp guarantee) — on a very high-volume host, a
  // destination whose events fall outside that window could be missing
  // even if still active. Same posture ProcessList.tsx's own comment
  // takes for /processes; not fixed here.
  const network = useNetwork();
  const [filter, setFilter] = useState("");

  const rows = (network.data ?? []).filter((row) =>
    `${row.dst_ip}:${row.dst_port}`.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Network</h1>
      <input
        type="text"
        placeholder="Filter by destination"
        aria-label="Filter by destination"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {network.isLoading && <p>Loading network connections…</p>}
      {network.isError && (
        <p role="alert">Failed to load network connections: {(network.error as Error).message}</p>
      )}
      {!network.isLoading && !network.isError && rows.length === 0 && <p>No network connections found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Destination</th>
              <th>Proto</th>
              <th>Host</th>
              <th>Last event</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.host_id}:${row.dst_ip}:${row.dst_port}:${row.proto}`}>
                <td>
                  <Link to={`/network/${row.dst_ip}`}>{`${row.dst_ip}:${row.dst_port}`}</Link>
                </td>
                <td>{row.proto}</td>
                <td>{row.hostname}</td>
                <td>{row.last_event_type}</td>
                <td>{row.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
