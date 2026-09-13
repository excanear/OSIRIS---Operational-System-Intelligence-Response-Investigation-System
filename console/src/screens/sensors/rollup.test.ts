import { describe, expect, it } from "vitest";
import type { CanonicalEvent } from "../../api/types";
import { rollupSensorHealth } from "./rollup";

function sensorHealthEvent(overrides: {
  hostId?: string;
  timestamp?: number;
  sensorName?: string;
  state?: "HEALTHY" | "DEGRADED" | "FAILED";
  lastError?: string;
  lastEventAt?: number | null;
}): CanonicalEvent {
  const {
    hostId = "host-1",
    timestamp = 1000,
    sensorName = "network",
    state = "HEALTHY",
    lastError,
    lastEventAt = timestamp,
  } = overrides;

  return {
    event_id: `evt-${timestamp}-${sensorName}`,
    event_type: "SENSOR_HEALTH",
    timestamp,
    host: { host_id: hostId, hostname: "h" },
    event_data: {
      sensor_name: sensorName,
      state: state === "HEALTHY" ? { state } : { state, last_error: lastError ?? "boom" },
      events_processed: 1,
      last_event_at: lastEventAt,
    },
  };
}

describe("rollupSensorHealth", () => {
  it("ignores events that are not SENSOR_HEALTH", () => {
    const events: CanonicalEvent[] = [
      { ...sensorHealthEvent({}), event_type: "PROCESS_EXEC" },
    ];
    expect(rollupSensorHealth(events)).toEqual([]);
  });

  it("produces one row per (host, sensor)", () => {
    const events = [
      sensorHealthEvent({ hostId: "host-1", sensorName: "network" }),
      sensorHealthEvent({ hostId: "host-1", sensorName: "exec" }),
      sensorHealthEvent({ hostId: "host-2", sensorName: "network" }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toHaveLength(3);
  });

  it("keeps the most recent event per (host, sensor)", () => {
    const events = [
      sensorHealthEvent({ timestamp: 1000, lastEventAt: 1000, state: "HEALTHY" }),
      sensorHealthEvent({
        timestamp: 2000,
        lastEventAt: 2000,
        state: "FAILED",
        lastError: "eBPF load failure: verifier rejected program",
      }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toHaveLength(1);
    expect(rows[0].state).toBe("FAILED");
    expect(rows[0].lastError).toBe("eBPF load failure: verifier rejected program");
  });

  it("surfaces the sensor name, state, and last_error fields", () => {
    const events = [
      sensorHealthEvent({
        hostId: "host-1",
        sensorName: "network",
        state: "DEGRADED",
        lastError: "queue overflow: dropped 12 events",
        lastEventAt: 5000,
      }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toEqual([
      {
        hostId: "host-1",
        sensorName: "network",
        state: "DEGRADED",
        lastError: "queue overflow: dropped 12 events",
        lastEventAt: 5000,
      },
    ]);
  });

  it("ignores malformed event_data instead of throwing", () => {
    const malformed: CanonicalEvent = {
      event_id: "evt-bad",
      event_type: "SENSOR_HEALTH",
      timestamp: 1000,
      host: { host_id: "host-1", hostname: "h" },
      event_data: { unexpected: "shape" },
    };

    expect(rollupSensorHealth([malformed])).toEqual([]);
  });

  it("sorts rows by sensor name", () => {
    const events = [
      sensorHealthEvent({ sensorName: "network" }),
      sensorHealthEvent({ hostId: "host-2", sensorName: "exec" }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows.map((r) => r.sensorName)).toEqual(["exec", "network"]);
  });

  it("uses event.timestamp for tie-breaking, not nullable last_event_at", () => {
    // Event A: later timestamp (5000), no last_event_at (null)
    const eventA = sensorHealthEvent({
      timestamp: 5000,
      lastEventAt: null,
      state: "HEALTHY",
    });
    // Event B: earlier timestamp (1000), has last_event_at (1000)
    const eventB = sensorHealthEvent({
      timestamp: 1000,
      lastEventAt: 1000,
      state: "FAILED",
      lastError: "earlier failure",
    });

    // Process A then B: A should win because timestamp 5000 > 1000
    const rowsAB = rollupSensorHealth([eventA, eventB]);
    expect(rowsAB).toHaveLength(1);
    expect(rowsAB[0].state).toBe("HEALTHY");
    expect(rowsAB[0].lastEventAt).toBeNull();

    // Process B then A: A should still win (same logic, not flipped by order)
    const rowsBA = rollupSensorHealth([eventB, eventA]);
    expect(rowsBA).toHaveLength(1);
    expect(rowsBA[0].state).toBe("HEALTHY");
    expect(rowsBA[0].lastEventAt).toBeNull();
  });
});
