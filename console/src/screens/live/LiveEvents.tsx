import { useState, type FormEvent } from "react";
import { useLiveEvents } from "../../api/liveEvents";

export function LiveEvents() {
  const [hostIdInput, setHostIdInput] = useState("");
  const [qInput, setQInput] = useState("");
  const [filter, setFilter] = useState<{ hostId?: string; q?: string }>({});

  const { events, connectionState, paused, setPaused, clear } = useLiveEvents(filter);

  function handleApplyFilter(event: FormEvent) {
    event.preventDefault();
    if (hostIdInput.trim()) {
      setFilter({ hostId: hostIdInput.trim() });
    } else if (qInput.trim()) {
      setFilter({ q: qInput.trim() });
    } else {
      setFilter({});
    }
  }

  const connectionLabel =
    connectionState === "live"
      ? "Live"
      : connectionState === "reconnecting"
        ? "Reconnecting…"
        : connectionState === "connecting"
          ? "Connecting…"
          : "Disconnected";

  return (
    <div>
      <h1>Live Events</h1>
      <p role="status">{connectionLabel}</p>
      <form onSubmit={handleApplyFilter}>
        <input
          type="text"
          aria-label="Host ID"
          placeholder="Host ID"
          value={hostIdInput}
          onChange={(event) => {
            setHostIdInput(event.target.value);
            setQInput("");
          }}
        />
        <input
          type="text"
          aria-label="OQL query"
          placeholder="OQL query"
          value={qInput}
          onChange={(event) => {
            setQInput(event.target.value);
            setHostIdInput("");
          }}
        />
        <button type="submit">Apply filter</button>
      </form>
      <button type="button" onClick={() => setPaused(!paused)}>
        {paused ? "Resume" : "Pause"}
      </button>
      <button type="button" onClick={clear}>
        Clear
      </button>
      {events.length === 0 && <p>No events yet.</p>}
      {events.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Event type</th>
              <th>Timestamp</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.event_id}>
                <td>{event.event_type}</td>
                <td>{event.timestamp}</td>
                <td>{event.host.hostname}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
