import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import * as client from "./client";
import { useAlerts, useEvents, useHealth, useIncidents, useProcess, useProcesses, useProcessStory } from "./hooks";

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

  it("useAlerts resolves with fetchAlerts's result", async () => {
    vi.spyOn(client, "fetchAlerts").mockResolvedValue([{ id: "a1" }]);

    const { result } = renderHook(() => useAlerts(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "a1" }]);
  });

  it("useIncidents resolves with fetchIncidents's result", async () => {
    vi.spyOn(client, "fetchIncidents").mockResolvedValue([{ id: "i1" }]);

    const { result } = renderHook(() => useIncidents(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "i1" }]);
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
});
