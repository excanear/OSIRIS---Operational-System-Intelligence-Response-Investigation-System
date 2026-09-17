import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  createEvidence,
  createIncident,
  fetchAlerts,
  fetchAllEvidence,
  fetchContainers,
  fetchContainerStory,
  fetchEvents,
  fetchEvidence,
  fetchFiles,
  fetchFileStory,
  fetchHealth,
  fetchIncident,
  fetchIncidents,
  fetchNetwork,
  fetchNetworkStory,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
  fetchSubgraph,
  fetchSystemStory,
  patchIncidentStatus,
} from "./client";
import { useAuthStore } from "../store/authStore";

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

  it("fetchEvents with q, until, and limit adds all three query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ q: 'event_type = "FILE_WRITE"', until: 2000, limit: 50 });

    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/events?q=event_type+%3D+%22FILE_WRITE%22&until=2000&limit=50'
    );
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

  it("fetchSubgraph calls /api/v1/graph/subgraph with the entity and optional params", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ nodes: [], edges: [], truncated: false }), { status: 200 })
    );

    await fetchSubgraph("IP:203.0.113.10", { depth: 3, maxNodes: 100, since: 1000, until: 2000 });

    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/graph/subgraph?entity=IP%3A203.0.113.10&depth=3&max_nodes=100&since=1000&until=2000"
    );
  });

  it("fetchSubgraph with no optional params only sends entity", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ nodes: [], edges: [], truncated: false }), { status: 200 })
    );

    await fetchSubgraph("IP:203.0.113.10");

    expect(fetch).toHaveBeenCalledWith("/api/v1/graph/subgraph?entity=IP%3A203.0.113.10");
  });

  it("fetchSystemStory calls /api/v1/system/story with host_id and optional since/until", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));

    await fetchSystemStory("host-1", { since: 1000, until: 2000 });

    expect(fetch).toHaveBeenCalledWith("/api/v1/system/story?host_id=host-1&since=1000&until=2000");
  });

  it("fetchSystemStory with no optional params only sends host_id", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));

    await fetchSystemStory("host-1");

    expect(fetch).toHaveBeenCalledWith("/api/v1/system/story?host_id=host-1");
  });

  it("fetchAllEvidence calls /api/v1/evidence with no query params", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAllEvidence();

    expect(fetch).toHaveBeenCalledWith("/api/v1/evidence");
  });

  it("fetchAllEvidence parses the {evidence, incident_ids} wire shape", async () => {
    const row = {
      evidence: {
        evidence_id: "e1",
        source: "MANUAL_UPLOAD",
        timestamp: 1000,
        integrity: { hash: "abc", immutable_since: 1000 },
        relationships: [],
        supersedes: null,
      },
      incident_ids: ["i1"],
    };
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([row]), { status: 200 }));

    const result = await fetchAllEvidence();

    expect(result).toEqual([row]);
  });

  it("fetchFiles calls /api/v1/files", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    await fetchFiles();
    expect(fetch).toHaveBeenCalledWith("/api/v1/files");
  });

  it("fetchNetwork calls /api/v1/network", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    await fetchNetwork();
    expect(fetch).toHaveBeenCalledWith("/api/v1/network");
  });

  it("fetchContainers calls /api/v1/containers", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    await fetchContainers();
    expect(fetch).toHaveBeenCalledWith("/api/v1/containers");
  });

  it("fetchFileStory calls /api/v1/files/story with an encoded file_id", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
    await fetchFileStory("1:100");
    expect(fetch).toHaveBeenCalledWith("/api/v1/files/story?file_id=1%3A100");
  });

  it("fetchNetworkStory calls /api/v1/network/story with the ip", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
    await fetchNetworkStory("93.184.216.34");
    expect(fetch).toHaveBeenCalledWith("/api/v1/network/story?ip=93.184.216.34");
  });

  it("fetchContainerStory calls /api/v1/containers/story with the container_id", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ events: [], alerts: [] }), { status: 200 }));
    await fetchContainerStory("abc123");
    expect(fetch).toHaveBeenCalledWith("/api/v1/containers/story?container_id=abc123");
  });

  describe("authenticated requests", () => {
    beforeEach(() => {
      sessionStorage.clear();
      useAuthStore.getState().clearSession();
    });

    it("attaches an Authorization header when a token is present", async () => {
      useAuthStore.getState().setSession({ token: "tok123", role: "ADMIN", username: "alice" });
      vi.mocked(fetch).mockResolvedValueOnce(
        new Response(JSON.stringify({ healthy: true, event_count: 0, last_write_at: 0 }), { status: 200 })
      );

      await fetchHealth();

      expect(fetch).toHaveBeenCalledWith("/api/v1/health", {
        headers: { Authorization: "Bearer tok123" },
      });
    });

    it("clears the session on a 401 response", async () => {
      useAuthStore.getState().setSession({ token: "tok123", role: "ADMIN", username: "alice" });
      vi.mocked(fetch).mockResolvedValueOnce(new Response("", { status: 401 }));

      await expect(fetchHealth()).rejects.toThrow();

      expect(useAuthStore.getState().token).toBeNull();
    });
  });
});
