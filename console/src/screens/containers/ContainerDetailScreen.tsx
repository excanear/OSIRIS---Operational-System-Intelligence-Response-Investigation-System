import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useContainerStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function ContainerDetailScreen() {
  const { containerId = "" } = useParams<{ containerId: string }>();
  const story = useContainerStory(containerId);
  const selectEntity = useUiStore((state) => state.selectEntity);

  useEffect(() => {
    selectEntity(`CONTAINER:${containerId}`);
    return () => selectEntity(null);
  }, [containerId, selectEntity]);

  return (
    <div>
      <h1>Container {containerId}</h1>
      <Link to="/graph" onClick={() => selectEntity(`CONTAINER:${containerId}`)}>
        View in Entity Graph
      </Link>
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="container story">
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
