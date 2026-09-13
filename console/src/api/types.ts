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

export interface ProcessRef {
  process_key: string;
  pid: number;
  exe_path: string;
  cmdline: string[];
  exe_hash: string | null;
  start_time_mono: number;
}

export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  process?: ProcessRef | null;
  parent_process?: ProcessRef | null;
  event_data: unknown;
}

export interface ProcessSummary {
  process_key: string;
  pid: number;
  exe_path: string;
  timestamp: number;
}

export interface ProcessDetail {
  process: CanonicalEvent;
  children: CanonicalEvent[];
}

export type AlertSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "SUPPRESSED";

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_version: number;
  rule_content_hash: string;
  severity: AlertSeverity;
  status: AlertStatus;
  timestamp: number;
  host_id: string;
  reasons: string[];
  evidence: string[];
}

export interface Story {
  events: CanonicalEvent[];
  alerts: Alert[];
}
