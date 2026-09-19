import type { TimeRange } from "./timeRange";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
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
  fetchHosts,
  fetchIncident,
  fetchIncidents,
  fetchNetwork,
  fetchNetworkStory,
  fetchProcess,
  fetchProcesses,
  fetchProcessStory,
  fetchSubgraph,
  fetchSystemStory,
  login,
  patchIncidentStatus,
} from "./client";
import { useAuthStore } from "../store/authStore";
import type { CreateEvidenceBody, EntityRef, IncidentStatus } from "./types";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
}

export function useEvents(
  eventType?: string,
  options: { since?: number; until?: number; limit?: number; q?: string; enabled?: boolean } = {}
) {
  const { since, until, limit, q, enabled } = options;
  return useQuery({
    queryKey: [
      "events",
      eventType ?? "all",
      since ?? "all-time",
      until ?? "all-time",
      limit ?? "default",
      q ?? "none",
    ],
    queryFn: () => fetchEvents({ eventType, since, until, limit, q }),
    enabled: enabled ?? true,
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

export function useProcesses(range?: TimeRange) {
  return useQuery({
    queryKey: ["processes", range ?? null],
    queryFn: () => fetchProcesses(range),
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

export function useFiles(range?: TimeRange) {
  return useQuery({
    queryKey: ["files", range ?? null],
    queryFn: () => fetchFiles(range),
  });
}

export function useNetwork(range?: TimeRange) {
  return useQuery({
    queryKey: ["network", range ?? null],
    queryFn: () => fetchNetwork(range),
  });
}

export function useContainers(range?: TimeRange) {
  return useQuery({
    queryKey: ["containers", range ?? null],
    queryFn: () => fetchContainers(range),
  });
}

export function useHosts() {
  return useQuery({
    queryKey: ["hosts"],
    queryFn: fetchHosts,
  });
}

export function useFileStory(fileId: string) {
  return useQuery({
    queryKey: ["file-story", fileId],
    queryFn: () => fetchFileStory(fileId),
    enabled: fileId.length > 0,
  });
}

export function useNetworkStory(ip: string) {
  return useQuery({
    queryKey: ["network-story", ip],
    queryFn: () => fetchNetworkStory(ip),
    enabled: ip.length > 0,
  });
}

export function useContainerStory(containerId: string) {
  return useQuery({
    queryKey: ["container-story", containerId],
    queryFn: () => fetchContainerStory(containerId),
    enabled: containerId.length > 0,
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

export function useSystemStory(hostId: string, params: { since?: number; until?: number } = {}) {
  return useQuery({
    queryKey: ["system-story", hostId, params.since ?? "all-time", params.until ?? "all-time"],
    queryFn: () => fetchSystemStory(hostId, params),
    enabled: hostId.length > 0,
  });
}

export function useAllEvidence() {
  return useQuery({
    queryKey: ["evidence", "all"],
    queryFn: fetchAllEvidence,
  });
}

export function useLogin() {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: (credentials: { username: string; password: string }) => login(credentials),
    onSuccess: (data, variables) => {
      setSession({
        token: data.token,
        role: data.role,
        username: variables.username,
        tenantId: data.tenant_id ?? null,
        tenantName: data.tenant_name ?? null,
      });
    },
  });
}
