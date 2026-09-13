import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import * as client from "./client";
import { useAlerts, useEvents, useHealth, useIncidents } from "./hooks";

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
});
