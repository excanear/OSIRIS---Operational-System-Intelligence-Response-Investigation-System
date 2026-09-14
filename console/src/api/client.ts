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
  Subgraph,
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const url = `${API_BASE}${path}`;
  // Preserve the exact fetch() call shape each verb used before this helper
  // existed (a bare `fetch(url)` for GET, an options object with a JSON
  // body for POST/PATCH) so existing call-site tests keep working unchanged.
  const response =
    body !== undefined
      ? await fetch(url, {
          method,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        })
      : method === "GET"
        ? await fetch(url)
        : await fetch(url, { method });
  if (!response.ok) {
    // Backend-side validation errors (e.g. "incident has no associated
    // entities to audit a transition against") arrive in the response
    // body, not the status code — surface them so the UI can show the
    // analyst *why* a mutation failed instead of a generic status string.
    let detail = "";
    try {
      detail = await response.text();
    } catch {
      // ignore: fall back to the status-only message below
    }
    const message = detail
      ? `${method} ${path} failed with status ${response.status}: ${detail}`
      : `${method} ${path} failed with status ${response.status}`;
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}

function apiGet<T>(path: string): Promise<T> {
  return request<T>("GET", path);
}

function apiPost<T>(path: string, body: unknown): Promise<T> {
  return request<T>("POST", path, body);
}

function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>("PATCH", path, body);
}

export function fetchHealth(): Promise<ApiHealth> {
  return apiGet<ApiHealth>("/health");
}

export function fetchEvents(
  params: { eventType?: string; since?: number; until?: number; limit?: number; q?: string } = {}
): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  if (params.since !== undefined) {
    // `since`/`until` mirror CanonicalEvent.timestamp (nanoseconds since
    // the Unix epoch, per crates/osiris-schema/src/envelope.rs and every
    // sensor's `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`),
    // not seconds or milliseconds.
    search.set("since", String(params.since));
  }
  if (params.q) {
    search.set("q", params.q);
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  if (params.limit !== undefined) {
    search.set("limit", String(params.limit));
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

export function fetchSubgraph(
  entity: string,
  params: { depth?: number; maxNodes?: number; since?: number; until?: number } = {}
): Promise<Subgraph> {
  const search = new URLSearchParams();
  search.set("entity", entity);
  if (params.depth !== undefined) {
    search.set("depth", String(params.depth));
  }
  if (params.maxNodes !== undefined) {
    search.set("max_nodes", String(params.maxNodes));
  }
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  return apiGet<Subgraph>(`/graph/subgraph?${search.toString()}`);
}

export function fetchSystemStory(hostId: string, params: { since?: number; until?: number } = {}): Promise<Story> {
  const search = new URLSearchParams();
  search.set("host_id", hostId);
  if (params.since !== undefined) {
    search.set("since", String(params.since));
  }
  if (params.until !== undefined) {
    search.set("until", String(params.until));
  }
  return apiGet<Story>(`/system/story?${search.toString()}`);
}
