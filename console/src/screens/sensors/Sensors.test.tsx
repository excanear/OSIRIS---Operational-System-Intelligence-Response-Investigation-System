import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Sensors } from "./Sensors";

vi.mock("../../api/hooks");

function mockEventsResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useEvents>;
}

describe("Sensors", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockEventsResult({ isLoading: true }));
    render(<Sensors />);
    expect(screen.getByText("Loading sensor health…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockEventsResult({ isError: true, error: new Error("network down") })
    );
    render(<Sensors />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state when there is no sensor health data", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockEventsResult({ data: [] }));
    render(<Sensors />);
    expect(screen.getByText("No sensor health data reported yet.")).toBeInTheDocument();
  });

  it("renders a row per sensor from the rollup", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockEventsResult({
        data: [
          {
            event_id: "evt-1",
            event_type: "SENSOR_HEALTH",
            timestamp: 5000,
            host: { host_id: "host-1", hostname: "web-01" },
            event_data: {
              sensor_name: "network",
              state: { state: "FAILED", last_error: "eBPF load failure" },
              events_processed: 10,
              last_event_at: 5000,
            },
          },
        ],
      })
    );

    render(<Sensors />);

    expect(screen.getByText("network")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByText("eBPF load failure")).toBeInTheDocument();
  });
});
