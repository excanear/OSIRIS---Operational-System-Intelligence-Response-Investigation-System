import { useAlerts, useHealth, useIncidents } from "../../api/hooks";

export function Overview() {
  const health = useHealth();
  const alerts = useAlerts();
  const incidents = useIncidents();

  return (
    <div>
      <h1>Overview</h1>
      <section aria-label="storage health">
        {health.isLoading && <p>Loading health…</p>}
        {health.isError && (
          <p role="alert">Failed to load health: {(health.error as Error).message}</p>
        )}
        {health.data && (
          <dl>
            <dt>Storage</dt>
            <dd>{health.data.healthy ? "Healthy" : "Unhealthy"}</dd>
            <dt>Event count</dt>
            <dd>{health.data.event_count}</dd>
          </dl>
        )}
      </section>
      <section aria-label="counts">
        <div>
          <span>Alerts</span>
          <strong>{alerts.isLoading ? "…" : alerts.isError ? "error" : (alerts.data?.length ?? 0)}</strong>
        </div>
        <div>
          <span>Incidents</span>
          <strong>
            {incidents.isLoading ? "…" : incidents.isError ? "error" : (incidents.data?.length ?? 0)}
          </strong>
        </div>
      </section>
    </div>
  );
}
