import { useHostPolicy } from "../../api/hooks";
import type { PolicySource } from "../../api/types";

function sourceLabel(source: PolicySource | null | undefined): string {
  if (!source) return "—";
  return source.group_name ? `Group ${source.group_name}` : "Platform policy";
}

export function HostPolicyPanel({ hostId }: { hostId: string }) {
  const query = useHostPolicy(hostId);
  if (query.isLoading) return <p>Loading policy…</p>;
  if (query.isError) return <p role="alert">Failed to load policy: {(query.error as Error).message}</p>;
  const v = query.data;
  if (!v) return null;
  const { effective, sources, last_delivery: delivery } = v;

  return (
    <section>
      <h2>Host policy</h2>
      <p>Status: {v.status}</p>
      <ul>
        <li>
          Telemetry level: {effective.telemetry_level ?? "Not set"} ({sourceLabel(sources.telemetry_level)})
        </li>
        {Object.keys(effective.sensors).map((n) => (
          <li key={n}>
            Sensor {n}: {effective.sensors[n] ? "On" : "Off"} ({sourceLabel(sources.sensors[n])})
          </li>
        ))}
        <li>
          Heartbeat (seconds): {effective.heartbeat_interval_secs ?? "Not set"} (
          {sourceLabel(sources.heartbeat_interval_secs)})
        </li>
      </ul>
      {delivery ? (
        <p>
          Last delivery: {delivery.result} at {new Date(delivery.sent_at / 1_000_000).toLocaleString()}
          {delivery.error ? ` — ${delivery.error}` : ""}
        </p>
      ) : (
        <p>No delivery yet.</p>
      )}
    </section>
  );
}
