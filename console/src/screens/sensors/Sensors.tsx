import { useMemo } from "react";
import { useEvents } from "../../api/hooks";
import { rollupSensorHealth } from "./rollup";

const ONE_HOUR_NS = 3_600 * 1_000_000_000;

export function Sensors() {
  // GET /events defaults to ORDER BY timestamp ASC with a 500-row cap
  // (osiris-query's DEFAULT_EVENT_LIMIT), so an unbounded query only ever
  // returns the *oldest* 500 SensorHealth events once a deployment has
  // accumulated more than that — this screen would freeze on stale data
  // forever. Bound the query to a recent window instead.
  const since = useMemo(() => Date.now() * 1_000_000 - ONE_HOUR_NS, []);
  const events = useEvents("SENSOR_HEALTH", { since });
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
