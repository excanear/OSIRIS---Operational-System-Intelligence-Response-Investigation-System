import { useState } from "react";
import { Link } from "react-router-dom";
import { useFiles } from "../../api/hooks";

export function FileList() {
  // GET /api/v1/files (files_handler in crates/osiris-api/src/lib.rs) dedups
  // by (host_id, FileIdentity) over a bounded query window capped at the
  // query plan's effective limit (EventQueryPlan::effective_limit() in
  // crates/osiris-query/src/plan.rs, currently 5,000 events), ordered ASC
  // by timestamp — so it only ever reflects the *oldest* matching FILE
  // events once a host has produced more than that many. On a very
  // high-volume host, a file whose events fall outside that window could
  // be missing even if it's still active. Same posture ProcessList.tsx's
  // own comment takes for /processes; not fixed here.
  const files = useFiles();
  const [filter, setFilter] = useState("");

  const rows = (files.data ?? []).filter((file) =>
    file.path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Filesystem</h1>
      <input
        type="text"
        placeholder="Filter by path"
        aria-label="Filter by path"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {files.isLoading && <p>Loading files…</p>}
      {files.isError && <p role="alert">Failed to load files: {(files.error as Error).message}</p>}
      {!files.isLoading && !files.isError && rows.length === 0 && <p>No files found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Path</th>
              <th>Host</th>
              <th>Last event</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((file) => (
              <tr key={file.file_id}>
                <td>
                  <Link to={`/files/${encodeURIComponent(file.file_id)}?host_id=${encodeURIComponent(file.host_id)}`}>{file.path}</Link>
                </td>
                <td>{file.hostname}</td>
                <td>{file.last_event_type}</td>
                <td>{file.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
