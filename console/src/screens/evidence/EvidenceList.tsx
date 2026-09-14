import { Link } from "react-router-dom";
import { useAllEvidence } from "../../api/hooks";

export function EvidenceList() {
  const evidence = useAllEvidence();
  const rows = evidence.data ?? [];

  return (
    <div>
      <h1>Evidence</h1>
      {evidence.isLoading && <p>Loading evidence…</p>}
      {evidence.isError && (
        <p role="alert">Failed to load evidence: {(evidence.error as Error).message}</p>
      )}
      {!evidence.isLoading && !evidence.isError && rows.length === 0 && <p>No evidence recorded.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Timestamp</th>
              <th>Hash</th>
              <th>Incidents</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.evidence.evidence_id}>
                <td>{row.evidence.source}</td>
                <td>{row.evidence.timestamp}</td>
                <td>{row.evidence.integrity.hash}</td>
                <td>
                  {row.incident_ids.length === 0
                    ? "—"
                    : row.incident_ids.map((id, index) => (
                        <span key={id}>
                          {index > 0 && ", "}
                          <Link to={`/incidents/${id}`}>{id}</Link>
                        </span>
                      ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
