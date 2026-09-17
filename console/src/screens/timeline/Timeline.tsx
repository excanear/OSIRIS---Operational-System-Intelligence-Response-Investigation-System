import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useEvents, useSystemStory } from "../../api/hooks";
import { parseOptionalNumber } from "../../api/numeric";
import { rollupSensorHealth } from "../sensors/rollup";

const ONE_HOUR_NS = 3_600 * 1_000_000_000;

export function Timeline() {
  const [searchParams] = useSearchParams();
  const [hostId, setHostId] = useState(searchParams.get("host") ?? "");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  // Same staleness guard as Sensors.tsx (7b-1): GET /events defaults to
  // ORDER BY timestamp ASC with a 500-row cap, so bound the window used
  // to discover known hosts to a recent range.
  const healthSince = useMemo(() => Date.now() * 1_000_000 - ONE_HOUR_NS, []);
  const healthEvents = useEvents("SENSOR_HEALTH", { since: healthSince });
  const hostIds = useMemo(() => {
    const rows = healthEvents.data ? rollupSensorHealth(healthEvents.data) : [];
    return Array.from(new Set(rows.map((row) => row.hostId))).sort();
  }, [healthEvents.data]);

  const parsedSince = parseOptionalNumber(since);
  const parsedUntil = parseOptionalNumber(until);
  const story = useSystemStory(hostId, { since: parsedSince, until: parsedUntil });

  function setLastHour() {
    setSince(String(Date.now() * 1_000_000 - ONE_HOUR_NS));
    setUntil("");
  }

  return (
    <div>
      <h1>Timeline</h1>
      <label>
        Host
        <select aria-label="Host" value={hostId} onChange={(event) => setHostId(event.target.value)}>
          <option value="">Select a host…</option>
          {hostIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
      </label>
      <input
        type="text"
        aria-label="Since (nanoseconds)"
        placeholder="Since (ns)"
        value={since}
        onChange={(event) => setSince(event.target.value)}
      />
      <input
        type="text"
        aria-label="Until (nanoseconds)"
        placeholder="Until (ns)"
        value={until}
        onChange={(event) => setUntil(event.target.value)}
      />
      <button type="button" onClick={setLastHour}>
        Last 1 hour
      </button>
      {!hostId && <p>Select a host to load its timeline.</p>}
      {hostId && story.isLoading && <p>Loading timeline…</p>}
      {hostId && story.isError && (
        <p role="alert">Failed to load timeline: {(story.error as Error).message}</p>
      )}
      {hostId && story.data && story.data.events.length === 0 && <p>No events in range.</p>}
      {hostId && story.data && story.data.events.length > 0 && (
        <ul>
          {story.data.events
            .slice()
            .sort((a, b) => a.timestamp - b.timestamp)
            .map((event) => (
              <li key={event.event_id}>
                <span>{event.category ?? "UNKNOWN"}</span> {event.event_type} @ {event.timestamp}
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}
