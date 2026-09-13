import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
}

export function useEvents(eventType?: string) {
  return useQuery({
    queryKey: ["events", eventType ?? "all"],
    queryFn: () => fetchEvents({ eventType }),
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
