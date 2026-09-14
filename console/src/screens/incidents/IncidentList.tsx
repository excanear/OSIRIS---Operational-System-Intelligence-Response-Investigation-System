import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useCreateIncident, useIncidents } from "../../api/hooks";
import { EntityRefInput, entityRefRowsToEntityRefs, type EntityRefRow } from "./EntityRefInput";

export function IncidentList() {
  const incidents = useIncidents();
  const createIncident = useCreateIncident();
  const navigate = useNavigate();
  const [rows, setRows] = useState<EntityRefRow[]>([{ kind: "IP", value: "" }]);
  const listRows = incidents.data ?? [];
  // An incident created with zero entities can never have its status
  // transitioned afterwards: IncidentStore::transition_status (in
  // crates/osiris-evidence/src/incident.rs) requires at least one entity
  // and returns a 500 error on any later PATCH. Compute this once per
  // render and reuse it for both the button's disabled state and the
  // submit guard, so a render/submit race can't slip an empty entity list
  // through.
  const entities = entityRefRowsToEntityRefs(rows);
  const hasNoEntities = entities.length === 0;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (hasNoEntities) {
      return;
    }
    const created = await createIncident.mutateAsync(entities);
    navigate(`/incidents/${created.incident_id}`);
  }

  return (
    <div>
      <h1>Incidents</h1>
      <form onSubmit={handleSubmit}>
        <h2>New incident</h2>
        <EntityRefInput rows={rows} onChange={setRows} />
        <button type="submit" disabled={createIncident.isPending || hasNoEntities}>
          Create incident
        </button>
        {createIncident.isError && (
          <p role="alert">Failed to create incident: {(createIncident.error as Error).message}</p>
        )}
      </form>
      {incidents.isLoading && <p>Loading incidents…</p>}
      {incidents.isError && (
        <p role="alert">Failed to load incidents: {(incidents.error as Error).message}</p>
      )}
      {!incidents.isLoading && !incidents.isError && listRows.length === 0 && <p>No incidents found.</p>}
      {listRows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Entities</th>
              <th>Alerts</th>
            </tr>
          </thead>
          <tbody>
            {listRows.map((incident) => (
              <tr key={incident.incident_id}>
                <td>
                  <Link to={`/incidents/${incident.incident_id}`}>{incident.status}</Link>
                </td>
                <td>{incident.entities.length}</td>
                <td>{incident.alert_ids.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
