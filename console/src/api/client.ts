import { timeRangeQuery, type TimeRange } from "./timeRange";
import type {
  Alert,
  ApiHealth,
  CanonicalEvent,
  ContainerSummary,
  CreateEvidenceBody,
  EntityRef,
  Evidence,
  EvidenceWithIncidents,
  FileSummary,
  GroupDetail,
  GroupPolicy,
  HostGroup,
  HostPolicyView,
  HostSummary,
  Incident,
  IncidentStatus,
  LoginResponse,
  NetworkSummary,
  ProcessDetail,
  ProcessSummary,
  Story,
  Subgraph,
} from "./types";
import { useAuthStore } from "../store/authStore";

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
  const token = useAuthStore.getState().token;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const hasHeaders = Object.keys(headers).length > 0;

  // Preserve the exact fetch() call shape each verb used before headers
  // existed (a bare `fetch(url)` for a headerless GET, `fetch(url,
  // {method})` for a headerless non-GET) whenever there's genuinely nothing
  // to attach — every existing call-site test runs with no token set and
  // asserts on that exact bare shape.
  const response =
    body !== undefined
      ? await fetch(url, { method, headers, body: JSON.stringify(body) })
      : method === "GET"
        ? hasHeaders
          ? await fetch(url, { headers })
          : await fetch(url)
        : hasHeaders
          ? await fetch(url, { method, headers })
          : await fetch(url, { method });

  if (!response.ok) {
    if (response.status === 401) {
      useAuthStore.getState().clearSession();
    }
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
  if (response.status === 204) {
    return undefined as T;
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

function apiPut<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("PUT", path, body);
}

function apiDelete<T>(path: string): Promise<T> {
  return request<T>("DELETE", path);
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

export function fetchProcesses(range?: TimeRange): Promise<ProcessSummary[]> {
  return apiGet<ProcessSummary[]>(`/processes${timeRangeQuery(range)}`);
}

export function fetchProcess(processKey: string): Promise<ProcessDetail> {
  return apiGet<ProcessDetail>(`/processes/${encodeURIComponent(processKey)}`);
}

export function fetchProcessStory(processKey: string): Promise<Story> {
  return apiGet<Story>(`/processes/${encodeURIComponent(processKey)}/story`);
}

export function fetchFiles(range?: TimeRange): Promise<FileSummary[]> {
  return apiGet<FileSummary[]>(`/files${timeRangeQuery(range)}`);
}

export function fetchNetwork(range?: TimeRange): Promise<NetworkSummary[]> {
  return apiGet<NetworkSummary[]>(`/network${timeRangeQuery(range)}`);
}

export function fetchContainers(range?: TimeRange): Promise<ContainerSummary[]> {
  return apiGet<ContainerSummary[]>(`/containers${timeRangeQuery(range)}`);
}

export function fetchHosts(group?: string): Promise<HostSummary[]> {
  return apiGet<HostSummary[]>(group ? `/hosts?group=${encodeURIComponent(group)}` : "/hosts");
}

export function fetchGroups(): Promise<HostGroup[]> {
  return apiGet<HostGroup[]>("/groups");
}

export function fetchGroup(groupId: string): Promise<GroupDetail> {
  return apiGet<GroupDetail>(`/groups/${encodeURIComponent(groupId)}`);
}

export function createGroup(body: { name: string }): Promise<HostGroup> {
  return apiPost<HostGroup>("/groups", body);
}

export function renameGroup(groupId: string, name: string): Promise<HostGroup> {
  return apiPatch<HostGroup>(`/groups/${encodeURIComponent(groupId)}`, { name });
}

export function deleteGroup(groupId: string): Promise<void> {
  return apiDelete<void>(`/groups/${encodeURIComponent(groupId)}`);
}

export function addGroupMember(groupId: string, hostId: string): Promise<void> {
  return apiPut<void>(
    `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(hostId)}`
  );
}

export function removeGroupMember(groupId: string, hostId: string): Promise<void> {
  return apiDelete<void>(
    `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(hostId)}`
  );
}

export function fetchGroupPolicy(groupId: string): Promise<{ policy: GroupPolicy | null }> {
  return apiGet<{ policy: GroupPolicy | null }>(`/groups/${encodeURIComponent(groupId)}/policy`);
}

export function putGroupPolicy(
  groupId: string,
  policy: GroupPolicy
): Promise<{ policy: GroupPolicy | null }> {
  return apiPut<{ policy: GroupPolicy | null }>(
    `/groups/${encodeURIComponent(groupId)}/policy`,
    policy
  );
}

export function deleteGroupPolicy(groupId: string): Promise<void> {
  return apiDelete<void>(`/groups/${encodeURIComponent(groupId)}/policy`);
}

export function fetchHostPolicy(hostId: string): Promise<HostPolicyView> {
  return apiGet<HostPolicyView>(`/hosts/${encodeURIComponent(hostId)}/policy`);
}

export function fetchFileStory(fileId: string): Promise<Story> {
  return apiGet<Story>(`/files/story?file_id=${encodeURIComponent(fileId)}`);
}

export function fetchNetworkStory(ip: string): Promise<Story> {
  return apiGet<Story>(`/network/story?ip=${encodeURIComponent(ip)}`);
}

export function fetchContainerStory(containerId: string): Promise<Story> {
  return apiGet<Story>(`/containers/story?container_id=${encodeURIComponent(containerId)}`);
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

export function fetchAllEvidence(): Promise<EvidenceWithIncidents[]> {
  return apiGet<EvidenceWithIncidents[]>("/evidence");
}

export function login(credentials: { username: string; password: string }): Promise<LoginResponse> {
  return apiPost<LoginResponse>("/auth/login", credentials);
}
