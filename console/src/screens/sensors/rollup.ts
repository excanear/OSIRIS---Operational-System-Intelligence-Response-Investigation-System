import type { CanonicalEvent, HealthState, SensorHealthEventData } from "../../api/types";

export type SensorRollupState = HealthState["state"];

export interface SensorRollupRow {
  hostId: string;
  sensorName: string;
  state: SensorRollupState;
  lastError: string | null;
  lastEventAt: number | null;
}

function isSensorHealthEventData(value: unknown): value is SensorHealthEventData {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.sensor_name !== "string") {
    return false;
  }
  if (typeof record.state !== "object" || record.state === null) {
    return false;
  }
  const state = (record.state as Record<string, unknown>).state;
  return state === "HEALTHY" || state === "DEGRADED" || state === "FAILED";
}

/**
 * Reduces SensorHealth events (ARCHITECTURE.md §23) to one row per
 * (host, sensor): the most recently reported event wins based on event.timestamp.
 */
export function rollupSensorHealth(events: CanonicalEvent[]): SensorRollupRow[] {
  const latest = new Map<string, SensorRollupRow>();
  const orderTime = new Map<string, number>();

  for (const event of events) {
    if (event.event_type !== "SENSOR_HEALTH") {
      continue;
    }
    if (!isSensorHealthEventData(event.event_data)) {
      continue;
    }

    const data = event.event_data;
    const key = `${event.host.host_id}:${data.sensor_name}`;
    const candidate: SensorRollupRow = {
      hostId: event.host.host_id,
      sensorName: data.sensor_name,
      state: data.state.state,
      lastError: data.state.state === "HEALTHY" ? null : data.state.last_error,
      lastEventAt: data.last_event_at,
    };

    const existingTime = orderTime.get(key);
    if (existingTime === undefined || event.timestamp >= existingTime) {
      latest.set(key, candidate);
      orderTime.set(key, event.timestamp);
    }
  }

  return Array.from(latest.values()).sort((a, b) => a.sensorName.localeCompare(b.sensorName));
}
