import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useProcess, useProcessStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function ProcessDetailScreen() {
  const { processKey = "" } = useParams<{ processKey: string }>();
  const detail = useProcess(processKey);
  const story = useProcessStory(processKey);
  const selectEntity = useUiStore((state) => state.selectEntity);

  useEffect(() => {
    selectEntity(processKey);
    return () => selectEntity(null);
  }, [processKey, selectEntity]);

  return (
    <div>
      <h1>Process {processKey}</h1>
      {detail.isLoading && <p>Loading process…</p>}
      {detail.isError && <p role="alert">Failed to load process: {(detail.error as Error).message}</p>}
      {detail.data && (
        <section aria-label="process detail">
          <dl>
            <dt>PID</dt>
            <dd>{detail.data.process.process?.pid ?? "—"}</dd>
            <dt>Exe path</dt>
            <dd>{detail.data.process.process?.exe_path ?? "—"}</dd>
          </dl>
          <h2>Children ({detail.data.children.length})</h2>
          <ul>
            {detail.data.children.map((child) => (
              <li key={child.event_id}>{child.process?.exe_path ?? child.event_id}</li>
            ))}
          </ul>
        </section>
      )}
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="process story">
          <h2>Related alerts ({story.data.alerts.length})</h2>
          <ul>
            {story.data.alerts.map((alert) => (
              <li key={alert.alert_id}>
                {alert.rule_id}: {alert.reasons.join("; ")}
              </li>
            ))}
          </ul>
          <h2>Events ({story.data.events.length})</h2>
        </section>
      )}
    </div>
  );
}
