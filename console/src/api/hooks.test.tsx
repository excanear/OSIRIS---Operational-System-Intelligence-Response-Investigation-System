import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import * as client from "./client";
import {
  useAlerts,
  useCreateEvidence,
  useCreateIncident,
  useEvents,
  useEvidence,
  useHealth,
  useIncident,
  useIncidents,
  usePatchIncidentStatus,
  useProcess,
  useProcesses,
  useProcessStory,
  useSubgraph,
  useSystemStory,
} from "./hooks";

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

describe("api hooks", () => {
  it("useHealth resolves with fetchHealth's result", async () => {
    vi.spyOn(client, "fetchHealth").mockResolvedValue({
      healthy: true,
      event_count: 3,
      last_write_at: 500,
    });

    const { result } = renderHook(() => useHealth(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual({ healthy: true, event_count: 3, last_write_at: 500 });
  });

  it("useEvents forwards the eventType to fetchEvents", async () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(() => useEvents("SENSOR_HEALTH"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ eventType: "SENSOR_HEALTH", since: undefined });
  });

  it("useEvents forwards the since option to fetchEvents", async () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(() => useEvents("SENSOR_HEALTH", { since: 1_700_000_000 }), {
      wrapper,
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ eventType: "SENSOR_HEALTH", since: 1_700_000_000 });
  });

  it("useEvents forwards q, until, limit, and enabled to fetchEvents/useQuery", async () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(
      () => useEvents(undefined, { q: 'event_type = "FILE_WRITE"', until: 2000, limit: 50, enabled: true }),
      { wrapper }
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({
      eventType: undefined,
      since: undefined,
      until: 2000,
      limit: 50,
      q: 'event_type = "FILE_WRITE"',
    });
  });

  it("useEvents does not fire when enabled is explicitly false", () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(() => useEvents(undefined, { enabled: false }), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("useAlerts resolves with fetchAlerts's result", async () => {
    const alert = {
      alert_id: "a1",
      rule_id: "rule_a",
      rule_version: 1,
      rule_content_hash: "hash",
      severity: "HIGH" as const,
      status: "OPEN" as const,
      timestamp: 1000,
      host_id: "host-1",
      reasons: ["suspicious activity"],
      evidence: ["evt-1"],
    };
    vi.spyOn(client, "fetchAlerts").mockResolvedValue([alert]);

    const { result } = renderHook(() => useAlerts(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([alert]);
  });

  it("useAlerts forwards ruleId and since to fetchAlerts", async () => {
    const spy = vi.spyOn(client, "fetchAlerts").mockResolvedValue([]);

    const { result } = renderHook(() => useAlerts({ ruleId: "rule_a", since: 1000 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ ruleId: "rule_a", since: 1000 });
  });

  it("useIncidents resolves with fetchIncidents's result", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    vi.spyOn(client, "fetchIncidents").mockResolvedValue([incident]);

    const { result } = renderHook(() => useIncidents(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([incident]);
  });

  it("useProcesses resolves with fetchProcesses's result", async () => {
    vi.spyOn(client, "fetchProcesses").mockResolvedValue([
      { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
    ]);

    const { result } = renderHook(() => useProcesses(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([
      { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
    ]);
  });

  it("useProcess forwards the processKey to fetchProcess", async () => {
    const spy = vi.spyOn(client, "fetchProcess").mockResolvedValue({
      process: { event_id: "e1", event_type: "PROCESS_EXEC", timestamp: 1000, host: { host_id: "h1", hostname: "h" }, event_data: {} },
      children: [],
    });

    const { result } = renderHook(() => useProcess("abc123"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123");
  });

  it("useProcessStory forwards the processKey to fetchProcessStory", async () => {
    const spy = vi.spyOn(client, "fetchProcessStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useProcessStory("abc123"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123");
  });

  it("useIncident forwards the incidentId to fetchIncident", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "fetchIncident").mockResolvedValue(incident);

    const { result } = renderHook(() => useIncident("i1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("i1");
  });

  it("useCreateIncident calls createIncident with the given entities", async () => {
    const incident = { incident_id: "i1", status: "NEW" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "createIncident").mockResolvedValue(incident);

    const { result } = renderHook(() => useCreateIncident(), { wrapper });
    await result.current.mutateAsync([{ kind: "IP", addr: "203.0.113.10" }]);

    expect(spy).toHaveBeenCalledWith([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("usePatchIncidentStatus calls patchIncidentStatus with the incidentId, status, and why", async () => {
    const incident = { incident_id: "i1", status: "INVESTIGATING" as const, entities: [], alert_ids: [], notes: [] };
    const spy = vi.spyOn(client, "patchIncidentStatus").mockResolvedValue(incident);

    const { result } = renderHook(() => usePatchIncidentStatus("i1"), { wrapper });
    await result.current.mutateAsync({ status: "INVESTIGATING", why: "starting" });

    expect(spy).toHaveBeenCalledWith("i1", "INVESTIGATING", "starting");
  });

  it("useEvidence forwards the incidentId to fetchEvidence", async () => {
    const spy = vi.spyOn(client, "fetchEvidence").mockResolvedValue([]);

    const { result } = renderHook(() => useEvidence("i1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("i1");
  });

  it("useCreateEvidence calls createEvidence with the incidentId merged into the body", async () => {
    const evidence = {
      evidence_id: "e1",
      source: "MANUAL_UPLOAD" as const,
      timestamp: 1000,
      integrity: { hash: "abc", immutable_since: 1000 },
      relationships: [],
      supersedes: null,
    };
    const spy = vi.spyOn(client, "createEvidence").mockResolvedValue(evidence);

    const { result } = renderHook(() => useCreateEvidence("i1"), { wrapper });
    await result.current.mutateAsync({
      source: "MANUAL_UPLOAD",
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
    });

    expect(spy).toHaveBeenCalledWith({
      source: "MANUAL_UPLOAD",
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
      incident_id: "i1",
    });
  });

  it("useSubgraph forwards the entity and params to fetchSubgraph", async () => {
    const spy = vi.spyOn(client, "fetchSubgraph").mockResolvedValue({ nodes: [], edges: [], truncated: false });

    const { result } = renderHook(() => useSubgraph("IP:203.0.113.10", { depth: 2 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("IP:203.0.113.10", { depth: 2 });
  });

  it("useSubgraph does not fire when the entity is an empty string", () => {
    const spy = vi.spyOn(client, "fetchSubgraph").mockResolvedValue({ nodes: [], edges: [], truncated: false });

    const { result } = renderHook(() => useSubgraph(""), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("useSystemStory forwards hostId and params to fetchSystemStory", async () => {
    const spy = vi.spyOn(client, "fetchSystemStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useSystemStory("host-1", { since: 1000 }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("host-1", { since: 1000 });
  });

  it("useSystemStory does not fire when hostId is an empty string", () => {
    const spy = vi.spyOn(client, "fetchSystemStory").mockResolvedValue({ events: [], alerts: [] });

    const { result } = renderHook(() => useSystemStory(""), { wrapper });

    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });
});
