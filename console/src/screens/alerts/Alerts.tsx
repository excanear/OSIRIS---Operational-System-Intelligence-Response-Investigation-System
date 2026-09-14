import { useMemo, useState } from "react";
import { useAlerts } from "../../api/hooks";

const ONE_HOUR_NS = 3_600 * 1_000_000_000;

export function Alerts() {
  const [ruleId, setRuleId] = useState("");
  // GET /alerts defaults to ORDER BY timestamp ASC with a 100-row cap
  // (AlertQueryPlan::new()'s default limit in osiris-storage), so an
  // unbounded query only ever returns the *oldest* 100 alerts once a
  // deployment has accumulated more than that — this screen would freeze on
  // stale data forever. Bound the query to a recent window instead.
  const since = useMemo(() => Date.now() * 1_000_000 - ONE_HOUR_NS, []);
  const alerts = useAlerts({ ruleId: ruleId || undefined, since });
  const rows = alerts.data ?? [];

  return (
    <div>
      <h1>Alerts</h1>
      <input
        type="text"
        placeholder="Filter by rule ID"
        aria-label="Filter by rule ID"
        value={ruleId}
        onChange={(event) => setRuleId(event.target.value)}
      />
      {alerts.isLoading && <p>Loading alerts…</p>}
      {alerts.isError && <p role="alert">Failed to load alerts: {(alerts.error as Error).message}</p>}
      {!alerts.isLoading && !alerts.isError && rows.length === 0 && <p>No alerts found.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Host</th>
              <th>Reasons</th>
              <th>Timestamp</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((alert) => (
              <tr key={alert.alert_id}>
                <td>{alert.rule_id}</td>
                <td>{alert.severity}</td>
                <td>{alert.status}</td>
                <td>{alert.host_id}</td>
                <td>{alert.reasons.join("; ")}</td>
                <td>{alert.timestamp}</td>
                <td>{alert.evidence.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
