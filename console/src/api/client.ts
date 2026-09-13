import type {
  Alert,
  ApiHealth,
  CanonicalEvent,
  CreateEvidenceBody,
  EntityRef,
  Evidence,
  Incident,
  IncidentStatus,
  ProcessDetail,
  ProcessSummary,
  Story,
} from "./types";

const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new ApiError(response.status, `GET ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new ApiError(response.status, `POST ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new ApiError(response.status, `PATCH ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

export function fetchHealth(): Promise<ApiHealth> {
  return apiGet<ApiHealth>("/health");
}

export function fetchEvents(
  params: { eventType?: string; since?: number } = {}
): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  if (params.since !== undefined) {
    // `since` mirrors CanonicalEvent.timestamp (nanoseconds since the Unix
    // epoch, per crates/osiris-schema/src/envelope.rs and every sensor's
    // `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`), not
    // seconds or milliseconds.
    search.set("since", String(params.since));
  }
  const queryString = search.toString();
  return apiGet<CanonicalEvent[]>(`/events${queryString ? `?${queryString}` : ""}`);
}

export function fetchAlerts(params: { ruleId?: string; since?: number } = {}): Promise<Alert[]> {
  const search = new URLSearchParams();
  if (params.ruleId) {
    search.set("rule_id", params.ruleId);
  }
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  const queryString = search.toString();
  return apiGet<Alert[]>(`/alerts${queryString ? `?${queryString}` : ""}`);
}

export function fetchIncidents(): Promise<Incident[]> {
  return apiGet<Incident[]>("/incidents");
}

export function fetchProcesses(): Promise<ProcessSummary[]> {
  return apiGet<ProcessSummary[]>("/processes");
}

export function fetchProcess(processKey: string): Promise<ProcessDetail> {
  return apiGet<ProcessDetail>(`/processes/${encodeURIComponent(processKey)}`);
}

export function fetchProcessStory(processKey: string): Promise<Story> {
  return apiGet<Story>(`/processes/${encodeURIComponent(processKey)}/story`);
}

export function fetchIncident(incidentId: string): Promise<Incident> {
  return apiGet<Incident>(`/incidents/${encodeURIComponent(incidentId)}`);
}

export function createIncident(entities: EntityRef[]): Promise<Incident> {
  return apiPost<Incident>("/incidents", { entities });
}

export function patchIncidentStatus(
  incidentId: string,
  status: IncidentStatus,
  why?: string
): Promise<Incident> {
  return apiPatch<Incident>(`/incidents/${encodeURIComponent(incidentId)}`, { status, why });
}

export function fetchEvidence(incidentId: string): Promise<Evidence[]> {
  return apiGet<Evidence[]>(`/evidence?incident_id=${encodeURIComponent(incidentId)}`);
}

export function createEvidence(body: CreateEvidenceBody): Promise<Evidence> {
  return apiPost<Evidence>("/evidence", body);
}
