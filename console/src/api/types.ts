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
  category?: string;
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

export type EntityRef =
  | { kind: "PROCESS"; process_key: string }
  | { kind: "FILE"; host_id: string; inode: number; device_id: number }
  | { kind: "IP"; addr: string }
  | { kind: "DOMAIN"; name: string }
  | { kind: "USER"; host_id: string; uid: number }
  | { kind: "CONTAINER"; container_id: string }
  | { kind: "SESSION"; session_id: string };

export type IncidentStatus = "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export interface Incident {
  incident_id: string;
  status: IncidentStatus;
  entities: EntityRef[];
  alert_ids: string[];
  notes: string[];
}

export type EvidenceSource = "EVENT_CAPTURE" | "FILE_SNAPSHOT" | "MANUAL_UPLOAD";

export interface Integrity {
  hash: string;
  immutable_since: number;
}

export interface Evidence {
  evidence_id: string;
  source: EvidenceSource;
  timestamp: number;
  integrity: Integrity;
  relationships: EntityRef[];
  supersedes: string | null;
}

export interface CreateEvidenceBody {
  source: EvidenceSource;
  hash: string;
  immutable_since: number;
  relationships: EntityRef[];
  supersedes?: string | null;
  incident_id?: string | null;
}

export type EntityKind = "PROCESS" | "FILE" | "IP" | "DOMAIN" | "USER" | "CONTAINER" | "SESSION";

export type Relation =
  | "SPAWNED"
  | "EXECUTED_AS"
  | "WROTE"
  | "READ"
  | "CONNECTED_TO"
  | "RESOLVED_TO"
  | "BELONGS_TO_CONTAINER"
  | "BELONGS_TO_POD"
  | "RUNS_IN_CGROUP"
  | "TRIGGERED_BY_SESSION";

export interface GraphNode {
  id: string;
  kind: EntityKind;
}

export interface GraphEdge {
  from: string;
  to: string;
  relation: Relation;
  event_id: string;
  timestamp: number;
}

export interface Subgraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}
