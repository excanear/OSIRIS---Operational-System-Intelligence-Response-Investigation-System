import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Alerts } from "./Alerts";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useAlerts>;
}

describe("Alerts", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ isLoading: true }));
    render(<Alerts />);
    expect(screen.getByText("Loading alerts…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    render(<Alerts />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }));
    render(<Alerts />);
    expect(screen.getByText("No alerts found.")).toBeInTheDocument();
  });

  it("renders a row per alert", () => {
    vi.mocked(hooks.useAlerts).mockReturnValue(
      mockQueryResult({
        data: [
          {
            alert_id: "a1",
            rule_id: "rule_a",
            rule_version: 1,
            rule_content_hash: "hash",
            severity: "HIGH",
            status: "OPEN",
            timestamp: 1000,
            host_id: "host-1",
            reasons: ["suspicious activity"],
            evidence: ["e1", "e2"],
          },
        ],
      })
    );
    render(<Alerts />);

    expect(screen.getByText("rule_a")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("OPEN")).toBeInTheDocument();
    expect(screen.getByText("suspicious activity")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("filters by rule ID via useAlerts", () => {
    const spy = vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }));
    render(<Alerts />);

    fireEvent.change(screen.getByLabelText("Filter by rule ID"), { target: { value: "rule_a" } });

    expect(spy).toHaveBeenLastCalledWith({ ruleId: "rule_a" });
  });
});
