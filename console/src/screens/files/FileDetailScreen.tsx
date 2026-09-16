import { useEffect } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useFileStory } from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";

export function FileDetailScreen() {
  const { fileId = "" } = useParams<{ fileId: string }>();
  const [searchParams] = useSearchParams();
  const hostId = searchParams.get("host_id");
  const story = useFileStory(fileId);
  const selectEntity = useUiStore((state) => state.selectEntity);

  // FileIdentity::as_key() (crates/osiris-schema/src/file_identity.rs)
  // formats fileId as "<device_id>:<inode>" — device_id first. But
  // EntityRef::File::storage_key() (crates/osiris-schema/src/relationships.rs)
  // formats as "FILE:<host_id>:<inode>:<device_id>" — inode first. The two
  // orders differ, so the split parts must be swapped when composing the key.
  const [deviceId, inode] = fileId.split(":");
  const entityKey = hostId && deviceId && inode ? `FILE:${hostId}:${inode}:${deviceId}` : null;

  useEffect(() => {
    if (!entityKey) {
      return undefined;
    }
    selectEntity(entityKey);
    return () => selectEntity(null);
  }, [entityKey, selectEntity]);

  return (
    <div>
      <h1>File {fileId}</h1>
      {entityKey && (
        <Link to="/graph" onClick={() => selectEntity(entityKey)}>
          View in Entity Graph
        </Link>
      )}
      {story.isLoading && <p>Loading story…</p>}
      {story.isError && <p role="alert">Failed to load story: {(story.error as Error).message}</p>}
      {story.data && (
        <section aria-label="file story">
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
