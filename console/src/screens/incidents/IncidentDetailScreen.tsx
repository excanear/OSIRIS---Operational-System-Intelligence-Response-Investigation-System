import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import {
  useCreateEvidence,
  useEvidence,
  useIncident,
  usePatchIncidentStatus,
} from "../../api/hooks";
import { describeEntityRef, entityRefToStorageKey } from "../../api/entityKey";
import type { IncidentStatus } from "../../api/types";
import { useUiStore } from "../../store/uiStore";

const INCIDENT_STATUSES: IncidentStatus[] = [
  "NEW",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export function IncidentDetailScreen() {
  const { incidentId = "" } = useParams<{ incidentId: string }>();
  const incident = useIncident(incidentId);
  const evidence = useEvidence(incidentId);
  const patchStatus = usePatchIncidentStatus(incidentId);
  const createEvidence = useCreateEvidence(incidentId);
  const selectEntity = useUiStore((state) => state.selectEntity);

  const [nextStatus, setNextStatus] = useState<IncidentStatus>("INVESTIGATING");
  const [why, setWhy] = useState("");
  const [hash, setHash] = useState("");
  const evidenceRows = evidence.data ?? [];

  async function handleStatusSubmit(event: FormEvent) {
    event.preventDefault();
    await patchStatus.mutateAsync({ status: nextStatus, why: why || undefined });
  }

  async function handleEvidenceSubmit(event: FormEvent) {
    event.preventDefault();
    await createEvidence.mutateAsync({
      source: "MANUAL_UPLOAD",
      hash,
      // Nanoseconds since the Unix epoch, matching CanonicalEvent.timestamp's
      // convention — never seconds or milliseconds.
      immutable_since: Date.now() * 1_000_000,
      relationships: [],
      supersedes: null,
    });
    setHash("");
  }

  return (
    <div>
      <h1>Incident {incidentId}</h1>
      {incident.isLoading && <p>Loading incident…</p>}
      {incident.isError && (
        <p role="alert">Failed to load incident: {(incident.error as Error).message}</p>
      )}
      {incident.data && (
        <section aria-label="incident detail">
          <dl>
            <dt>Status</dt>
            <dd>{incident.data.status}</dd>
            <dt>Entities</dt>
            <dd>
              {incident.data.entities.length === 0 ? (
                "0"
              ) : (
                <ul>
                  {incident.data.entities.map((entity, index) => (
                    <li key={index}>
                      {describeEntityRef(entity)}{" "}
                      <Link to="/graph" onClick={() => selectEntity(entityRefToStorageKey(entity))}>
                        View in Entity Graph
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt>Alerts</dt>
            <dd>{incident.data.alert_ids.length}</dd>
          </dl>
          <h2>Notes</h2>
          {incident.data.notes.length === 0 ? (
            <p>No notes.</p>
          ) : (
            <ul>
              {incident.data.notes.map((note, index) => (
                <li key={index}>{note}</li>
              ))}
            </ul>
          )}
        </section>
      )}
      <form onSubmit={handleStatusSubmit}>
        <h2>Change status</h2>
        <select
          aria-label="New status"
          value={nextStatus}
          onChange={(event) => setNextStatus(event.target.value as IncidentStatus)}
        >
          {INCIDENT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
        <input
          type="text"
          aria-label="Reason"
          placeholder="Reason (optional)"
          value={why}
          onChange={(event) => setWhy(event.target.value)}
        />
        <button type="submit" disabled={patchStatus.isPending}>
          Update status
        </button>
        {patchStatus.isError && (
          <p role="alert">Failed to update status: {(patchStatus.error as Error).message}</p>
        )}
      </form>
      <section aria-label="evidence">
        <h2>Evidence</h2>
        {evidence.isLoading && <p>Loading evidence…</p>}
        {evidence.isError && (
          <p role="alert">Failed to load evidence: {(evidence.error as Error).message}</p>
        )}
        {!evidence.isLoading && !evidence.isError && evidenceRows.length === 0 && (
          <p>No evidence recorded.</p>
        )}
        {evidenceRows.length > 0 && (
          <ul>
            {evidenceRows.map((item) => (
              <li key={item.evidence_id}>
                {item.source} — {item.integrity.hash}
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={handleEvidenceSubmit}>
          <h3>Record evidence</h3>
          <input
            type="text"
            aria-label="Evidence hash"
            placeholder="Integrity hash"
            value={hash}
            onChange={(event) => setHash(event.target.value)}
            required
          />
          <button type="submit" disabled={createEvidence.isPending}>
            Add evidence
          </button>
          {createEvidence.isError && (
            <p role="alert">Failed to record evidence: {(createEvidence.error as Error).message}</p>
          )}
        </form>
      </section>
    </div>
  );
}
