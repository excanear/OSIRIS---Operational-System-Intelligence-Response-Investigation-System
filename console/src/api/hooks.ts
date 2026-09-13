import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";

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
