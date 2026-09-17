import { Link } from "react-router-dom";
import { useHosts } from "../../api/hooks";

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
                <td>{row.last_seen}</td>
                <td>{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
