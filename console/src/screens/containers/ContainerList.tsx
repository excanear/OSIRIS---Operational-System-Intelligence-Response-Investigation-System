import { useState } from "react";
import { Link } from "react-router-dom";
import { useContainers } from "../../api/hooks";

export function ContainerList() {
  // GET /api/v1/containers (containers_handler in
  // crates/osiris-api/src/lib.rs) dedups by container_id alone over a
  // bounded query window capped at the query plan's effective limit
  // (EventQueryPlan::effective_limit() in crates/osiris-query/src/plan.rs,
  // currently 5,000 events), ordered ASC by timestamp — so it only ever
  // reflects the *oldest* matching CONTAINER events once a host has
  // produced more than that many. On a very high-volume host, a container
  // whose events fall outside that window could be missing even if still
  // active. Same posture ProcessList.tsx's own comment takes for
  // /processes; not fixed here.
  const containers = useContainers();
  const [filter, setFilter] = useState("");

  const rows = (containers.data ?? []).filter((row) => {
    const needle = filter.toLowerCase();
    return row.image.toLowerCase().includes(needle) || row.container_id.toLowerCase().includes(needle);
  });

  return (
    <div>
      <h1>Containers</h1>
      <input
        type="text"
        placeholder="Filter by image or container ID"
        aria-label="Filter by image or container ID"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {containers.isLoading && <p>Loading containers…</p>}
      {containers.isError && (
        <p role="alert">Failed to load containers: {(containers.error as Error).message}</p>
      )}
      {!containers.isLoading && !containers.isError && rows.length === 0 && <p>No containers found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Container ID</th>
              <th>Image</th>
              <th>Host</th>
              <th>Status</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.container_id}>
                <td>
                  <Link to={`/containers/${row.container_id}`}>{row.container_id}</Link>
                </td>
                <td>{row.image}</td>
                <td>{row.hostname}</td>
                <td>{row.status}</td>
                <td>{row.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
