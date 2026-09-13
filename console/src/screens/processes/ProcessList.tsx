import { useState } from "react";
import { Link } from "react-router-dom";
import { useProcesses } from "../../api/hooks";

export function ProcessList() {
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
