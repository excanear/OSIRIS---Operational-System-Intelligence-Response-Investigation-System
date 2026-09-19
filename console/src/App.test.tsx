import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { NAV_ITEMS } from "./app/navItems";
import { useAuthStore } from "./store/authStore";

describe("App", () => {
  beforeEach(() => {
    useAuthStore.getState().setSession({ token: "test-token", role: "ADMIN", username: "test-user" });
  });

  it("renders every nav item's label", () => {
    render(<App />);
    const nav = screen.getByRole("navigation", { name: "main" });
    for (const item of NAV_ITEMS) {
      expect(within(nav).getByText(item.label)).toBeInTheDocument();
    }
  });

  it("shows the Overview screen at the root path", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders exactly fourteen nav links, for Overview, Live Events, Process Explorer, Filesystem, Network, Containers, Hosts, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(14);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Live Events",
      "Process Explorer",
      "Filesystem",
      "Network",
      "Containers",
      "Hosts",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Evidence",
      "Sensors",
    ]);
  });

  it("shows the tenant name and keeps Incidents and Evidence available to a tenant user", () => {
    useAuthStore.getState().setSession({
      token: "t", role: "ADMIN", username: "u", tenantId: "t1", tenantName: "Acme",
    });
    render(<App />);
    const nav = screen.getByRole("navigation", { name: "main" });
    expect(within(nav).getByText("Acme")).toBeInTheDocument();
    expect(within(nav).getByText("Incidents")).toBeInTheDocument();
    expect(within(nav).getByText("Evidence")).toBeInTheDocument();
    expect(within(nav).getByText("Alerts")).toBeInTheDocument();
  });
});
