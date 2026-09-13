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

  it("shows the Overview 'coming soon' placeholder at the root path", () => {
    render(<App />);
    expect(screen.getByText("This screen is not implemented yet.")).toBeInTheDocument();
  });

  it("renders no nav links yet, since no item is enabled", () => {
    render(<App />);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
});
