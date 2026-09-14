import { useState, type ChangeEvent, type FormEvent } from "react";
import { useEvents } from "../../api/hooks";
import { parseOptionalNumber } from "../../api/numeric";
import { HUNT_TEMPLATES } from "./templates";

export function ThreatHunting() {
  const [query, setQuery] = useState("");
  const [ranQuery, setRanQuery] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [limit, setLimit] = useState("");

  const results = useEvents(undefined, {
    q: ranQuery || undefined,
    since: parseOptionalNumber(since),
    until: parseOptionalNumber(until),
    limit: parseOptionalNumber(limit),
    enabled: ranQuery.length > 0,
  });

  function handleTemplateSelect(event: ChangeEvent<HTMLSelectElement>) {
    const template = HUNT_TEMPLATES.find((t) => t.name === event.target.value);
    if (template) {
      setQuery(template.query);
    }
  }

  function handleRun(event: FormEvent) {
    event.preventDefault();
    setRanQuery(query);
  }

  return (
    <div>
      <h1>Threat Hunting</h1>
      <form onSubmit={handleRun}>
        <label>
          Template
          <select aria-label="Template" defaultValue="" onChange={handleTemplateSelect}>
            <option value="">Choose a template…</option>
            {HUNT_TEMPLATES.map((template) => (
              <option key={template.name} value={template.name}>
                {template.label}
              </option>
            ))}
          </select>
        </label>
        <textarea
          aria-label="OQL query"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
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
        <input
          type="text"
          aria-label="Limit"
          placeholder="Limit"
          value={limit}
          onChange={(event) => setLimit(event.target.value)}
        />
        <button type="submit" disabled={!query.trim()}>
          Run
        </button>
      </form>
      {ranQuery && results.isLoading && <p>Running query…</p>}
      {ranQuery && results.isError && (
        <p role="alert">Query failed: {(results.error as Error).message}</p>
      )}
      {ranQuery && results.data && results.data.length === 0 && <p>No matching events.</p>}
      {ranQuery && results.data && results.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Event type</th>
              <th>Timestamp</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>
            {results.data.map((event) => (
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
