import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("fetchHealth calls /api/v1/health and parses the response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ healthy: true, event_count: 42, last_write_at: 1000 }), {
        status: 200,
      })
    );

    const health = await fetchHealth();

    expect(fetch).toHaveBeenCalledWith("/api/v1/health");
    expect(health).toEqual({ healthy: true, event_count: 42, last_write_at: 1000 });
  });

  it("fetchEvents with no eventType calls /api/v1/events with no query string", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents();

    expect(fetch).toHaveBeenCalledWith("/api/v1/events");
  });

  it("fetchEvents with an eventType adds the event_type query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ eventType: "SENSOR_HEALTH" });

    expect(fetch).toHaveBeenCalledWith("/api/v1/events?event_type=SENSOR_HEALTH");
  });

  it("fetchEvents with a since adds the since query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ since: 1_700_000_000_000_000_000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/events?since=1700000000000000000");
  });

  it("fetchEvents with an eventType and since combines both query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ eventType: "SENSOR_HEALTH", since: 1000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/events?event_type=SENSOR_HEALTH&since=1000");
  });

  it("fetchAlerts calls /api/v1/alerts", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts();

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts");
  });

  it("fetchIncidents calls /api/v1/incidents", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchIncidents();

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents");
  });

  it("throws ApiError when the response is not ok", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));

    await expect(fetchHealth()).rejects.toThrow(ApiError);
  });
});
