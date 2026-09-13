export interface NavItem {
  label: string;
  path: string;
  enabled: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Overview", path: "/", enabled: false },
  { label: "Live Events", path: "/live-events", enabled: false },
  { label: "Process Explorer", path: "/processes", enabled: false },
  { label: "Filesystem", path: "/files", enabled: false },
  { label: "Network", path: "/network", enabled: false },
  { label: "Containers", path: "/containers", enabled: false },
  { label: "Timeline", path: "/timeline", enabled: false },
  { label: "Alerts", path: "/alerts", enabled: false },
  { label: "Incidents", path: "/incidents", enabled: false },
  { label: "Threat Hunting", path: "/hunting", enabled: false },
  { label: "Entity Graph", path: "/graph", enabled: false },
  { label: "Evidence", path: "/evidence", enabled: false },
  { label: "Sensors", path: "/sensors", enabled: false },
];
