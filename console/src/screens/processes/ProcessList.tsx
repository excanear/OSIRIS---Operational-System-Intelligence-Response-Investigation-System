import { useState } from "react";
import { Link } from "react-router-dom";
import { useProcesses } from "../../api/hooks";

export function ProcessList() {
  // GET /api/v1/processes takes no query parameters at all: the handler
  // (processes_handler in crates/osiris-api/src/lib.rs) always derives its
  // rows from EventQueryPlan::effective_limit()'s 500-event cap, ordered
  // ASC, so it only ever reflects the *oldest* 500 PROCESS_EXEC events once
  // a host has produced more than that — this list can go stale forever on
  // a busy host, with no way for the console to request a recent window.
  // Fixing this requires adding a since/pagination param to the backend
  // endpoint, which is out of scope for this phase (no backend changes).
  const processes = useProcesses();
  const [filter, setFilter] = useState("");

  const rows = (processes.data ?? []).filter((process) =>
    process.exe_path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <h1>Process Explorer</h1>
      <input
        type="text"
        placeholder="Filter by exe path"
        aria-label="Filter by exe path"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
      />
      {processes.isLoading && <p>Loading processes…</p>}
      {processes.isError && (
        <p role="alert">Failed to load processes: {(processes.error as Error).message}</p>
      )}
      {!processes.isLoading && !processes.isError && rows.length === 0 && <p>No processes found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>PID</th>
              <th>Exe path</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((process) => (
              <tr key={process.process_key}>
                <td>{process.pid}</td>
                <td>
                  <Link to={`/processes/${process.process_key}`}>{process.exe_path}</Link>
                </td>
                <td>{process.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
