import type { ApiHealth, CanonicalEvent } from "./types";

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

export function fetchHealth(): Promise<ApiHealth> {
  return apiGet<ApiHealth>("/health");
}

export function fetchEvents(params: { eventType?: string } = {}): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  const queryString = search.toString();
  return apiGet<CanonicalEvent[]>(`/events${queryString ? `?${queryString}` : ""}`);
}

export function fetchAlerts(): Promise<unknown[]> {
  return apiGet<unknown[]>("/alerts");
}

export function fetchIncidents(): Promise<unknown[]> {
  return apiGet<unknown[]>("/incidents");
}
