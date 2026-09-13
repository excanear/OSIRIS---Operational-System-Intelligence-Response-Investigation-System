import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents, fetchProcess, fetchProcesses, fetchProcessStory } from "./client";

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

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: fetchAlerts,
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
