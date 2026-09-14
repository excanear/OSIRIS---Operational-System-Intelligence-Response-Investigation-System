import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  createEvidence,
  createIncident,
  fetchAlerts,
  fetchEvents,
  fetchEvidence,
  fetchHealth,
  fetchIncident,
  fetchIncidents,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
  patchIncidentStatus,
} from "./client";

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

  it("fetchAlerts with a ruleId adds the rule_id query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ ruleId: "rule_a" });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?rule_id=rule_a");
  });

  it("fetchAlerts with a since adds the since query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ since: 1000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?since=1000");
  });

  it("fetchAlerts with a ruleId and since combines both query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts({ ruleId: "rule_a", since: 1000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts?rule_id=rule_a&since=1000");
  });

  it("fetchIncidents calls /api/v1/incidents", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchIncidents();

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents");
  });

  it("throws ApiError when the response is not ok, including the response body text", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));

    let caught: unknown;
    try {
      await fetchHealth();
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).message).toMatch(/boom/);
  });

  it("throws ApiError with the response body text on a POST failure", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("incident has no associated entities to audit a transition against", {
        status: 500,
      })
    );

    await expect(createIncident([{ kind: "IP", addr: "203.0.113.10" }])).rejects.toThrow(
      /incident has no associated entities to audit a transition against/
    );
  });

  it("throws ApiError with the response body text on a PATCH failure", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("invalid incident_id: not-a-real-id", { status: 400 })
    );

    await expect(patchIncidentStatus("not-a-real-id", "INVESTIGATING")).rejects.toThrow(
      /invalid incident_id: not-a-real-id/
    );
  });

  it("fetchProcesses calls /api/v1/processes", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchProcesses();

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes");
  });

  it("fetchProcess calls /api/v1/processes/:processKey", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ process: {}, children: [] }), { status: 200 })
    );

    await fetchProcess("abc123");

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes/abc123");
  });

  it("fetchProcessStory calls /api/v1/processes/:processKey/story", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 })
    );

    await fetchProcessStory("abc123");

    expect(fetch).toHaveBeenCalledWith("/api/v1/processes/abc123/story");
  });

  it("fetchIncident calls /api/v1/incidents/:incidentId", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await fetchIncident("i1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents/i1");
  });

  it("createIncident POSTs to /api/v1/incidents with the entities body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await createIncident([{ kind: "IP", addr: "203.0.113.10" }]);

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entities: [{ kind: "IP", addr: "203.0.113.10" }] }),
    });
  });

  it("patchIncidentStatus PATCHes /api/v1/incidents/:incidentId with status and why", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({ incident_id: "i1", status: "INVESTIGATING", entities: [], alert_ids: [], notes: [] }),
        { status: 200 }
      )
    );

    await patchIncidentStatus("i1", "INVESTIGATING", "starting investigation");

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents/i1", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "INVESTIGATING", why: "starting investigation" }),
    });
  });

  it("fetchEvidence calls /api/v1/evidence with the incident_id query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvidence("i1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence?incident_id=i1");
  });

  it("createEvidence POSTs to /api/v1/evidence with the given body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          evidence_id: "e1",
          source: "MANUAL_UPLOAD",
          timestamp: 1000,
          integrity: { hash: "abc", immutable_since: 1000 },
          relationships: [],
          supersedes: null,
        }),
        { status: 200 }
      )
    );

    const body = {
      source: "MANUAL_UPLOAD" as const,
      hash: "abc",
      immutable_since: 1000,
      relationships: [],
      supersedes: null,
      incident_id: "i1",
    };
    await createEvidence(body);

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  });

  it("fetchIncidents parses a real Incident shape", async () => {
    const incident = { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([incident]), { status: 200 }));

    const incidents = await fetchIncidents();

    expect(incidents).toEqual([incident]);
  });
});
