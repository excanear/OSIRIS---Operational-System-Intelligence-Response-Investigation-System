export interface ApiHealth {
  healthy: boolean;
  event_count: number;
  last_write_at: number | null;
}

export type HealthState =
  | { state: "HEALTHY" }
  | { state: "DEGRADED"; last_error: string }
  | { state: "FAILED"; last_error: string };

export interface SensorHealthEventData {
  sensor_name: string;
  state: HealthState;
  events_processed: number;
  last_event_at: number | null;
}

export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  event_data: unknown;
}
