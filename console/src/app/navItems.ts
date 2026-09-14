export interface NavItem {
  label: string;
  path: string;
  enabled: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Overview", path: "/", enabled: true },
  { label: "Live Events", path: "/live-events", enabled: false },
  { label: "Process Explorer", path: "/processes", enabled: true },
  { label: "Filesystem", path: "/files", enabled: false },
  { label: "Network", path: "/network", enabled: false },
  { label: "Containers", path: "/containers", enabled: false },
  { label: "Timeline", path: "/timeline", enabled: true },
  { label: "Alerts", path: "/alerts", enabled: true },
  { label: "Incidents", path: "/incidents", enabled: true },
  { label: "Threat Hunting", path: "/hunting", enabled: true },
  { label: "Entity Graph", path: "/graph", enabled: true },
  { label: "Evidence", path: "/evidence", enabled: true },
  { label: "Sensors", path: "/sensors", enabled: true },
];
