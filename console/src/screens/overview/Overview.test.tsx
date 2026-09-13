import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Overview } from "./Overview";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  };
}

describe("Overview", () => {
  it("shows loading state while health is loading", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useHealth>);
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useAlerts>);
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useIncidents>);

    render(<Overview />);

    expect(screen.getByText("Loading health…")).toBeInTheDocument();
  });

  it("shows storage health and counts once loaded", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(
      mockQueryResult({ data: { healthy: true, event_count: 1234, last_write_at: 999 } }) as ReturnType<typeof hooks.useHealth>
    );
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [1, 2, 3] }) as ReturnType<typeof hooks.useAlerts>);
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [1] }) as ReturnType<typeof hooks.useIncidents>);

    render(<Overview />);

    expect(screen.getByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("1234")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
  });

  it("shows an error when health fails to load", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") }) as ReturnType<typeof hooks.useHealth>
    );
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useAlerts>);
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useIncidents>);

    render(<Overview />);

    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });
});
