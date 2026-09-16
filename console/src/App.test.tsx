import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { NAV_ITEMS } from "./app/navItems";

describe("App", () => {
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

  it("renders exactly thirteen nav links, for Overview, Live Events, Process Explorer, Filesystem, Network, Containers, Timeline, Alerts, Incidents, Threat Hunting, Entity Graph, Evidence, and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(13);
    expect(links.map((link) => link.textContent)).toEqual([
      "Overview",
      "Live Events",
      "Process Explorer",
      "Filesystem",
      "Network",
      "Containers",
      "Timeline",
      "Alerts",
      "Incidents",
      "Threat Hunting",
      "Entity Graph",
      "Evidence",
      "Sensors",
    ]);
  });
});
