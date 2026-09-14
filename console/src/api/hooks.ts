import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
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
  fetchSubgraph,
  patchIncidentStatus,
} from "./client";
import type { CreateEvidenceBody, EntityRef, IncidentStatus } from "./types";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
}

export function useEvents(eventType?: string, options: { since?: number } = {}) {
  const { since } = options;
  return useQuery({
    queryKey: ["events", eventType ?? "all", since ?? "all-time"],
    queryFn: () => fetchEvents({ eventType, since }),
  });
}

export function useAlerts(params: { ruleId?: string; since?: number } = {}) {
  const { ruleId, since } = params;
  return useQuery({
    queryKey: ["alerts", ruleId ?? "all", since ?? "all-time"],
    queryFn: () => fetchAlerts({ ruleId, since }),
  });
}

export function useIncidents() {
  return useQuery({
    queryKey: ["incidents"],
    queryFn: fetchIncidents,
  });
}

export function useProcesses() {
  return useQuery({
    queryKey: ["processes"],
    queryFn: fetchProcesses,
  });
}

export function useProcess(processKey: string) {
  return useQuery({
    queryKey: ["process", processKey],
    queryFn: () => fetchProcess(processKey),
  });
}

export function useProcessStory(processKey: string) {
  return useQuery({
    queryKey: ["process-story", processKey],
    queryFn: () => fetchProcessStory(processKey),
  });
}

export function useIncident(incidentId: string) {
  return useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => fetchIncident(incidentId),
  });
}

export function useCreateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (entities: EntityRef[]) => createIncident(entities),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function usePatchIncidentStatus(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ status, why }: { status: IncidentStatus; why?: string }) =>
      patchIncidentStatus(incidentId, status, why),
    onSuccess: (updated) => {
      queryClient.setQueryData(["incident", incidentId], updated);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useEvidence(incidentId: string) {
  return useQuery({
    queryKey: ["evidence", incidentId],
    queryFn: () => fetchEvidence(incidentId),
  });
}

export function useCreateEvidence(incidentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: Omit<CreateEvidenceBody, "incident_id">) =>
      createEvidence({ ...body, incident_id: incidentId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["evidence", incidentId] });
    },
  });
}

export function useSubgraph(
  entity: string,
  params: { depth?: number; maxNodes?: number; since?: number; until?: number } = {}
) {
  return useQuery({
    queryKey: [
      "subgraph",
      entity,
      params.depth ?? "default",
      params.maxNodes ?? "default",
      params.since ?? "all-time",
      params.until ?? "all-time",
    ],
    queryFn: () => fetchSubgraph(entity, params),
    enabled: entity.length > 0,
  });
}
