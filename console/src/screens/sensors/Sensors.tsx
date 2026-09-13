import { useEvents } from "../../api/hooks";
import { rollupSensorHealth } from "./rollup";

export function Sensors() {
  const events = useEvents("SENSOR_HEALTH");
  const rows = events.data ? rollupSensorHealth(events.data) : [];

  return (
    <div>
      <h1>Sensors</h1>
      {events.isLoading && <p>Loading sensor health…</p>}
      {events.isError && (
        <p role="alert">Failed to load sensor health: {(events.error as Error).message}</p>
      )}
      {!events.isLoading && !events.isError && rows.length === 0 && (
        <p>No sensor health data reported yet.</p>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Sensor</th>
              <th>State</th>
              <th>Last error</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.hostId}:${row.sensorName}`}>
                <td>{row.hostId}</td>
                <td>{row.sensorName}</td>
                <td>{row.state}</td>
                <td>{row.lastError ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
