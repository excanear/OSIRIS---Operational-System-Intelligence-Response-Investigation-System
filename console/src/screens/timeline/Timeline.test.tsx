import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Timeline } from "./Timeline";

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

const sensorHealthEvent = (hostId: string) => ({
  event_id: `sh-${hostId}`,
  event_type: "SENSOR_HEALTH",
  timestamp: 1000,
  host: { host_id: hostId, hostname: hostId },
  event_data: { sensor_name: "process", state: { state: "HEALTHY" }, events_processed: 1, last_event_at: 1000 },
});

describe("Timeline", () => {
  it("shows a host dropdown populated from sensor health events, with none selected by default", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a"), sensorHealthEvent("host-b")] }) as ReturnType<
        typeof hooks.useEvents
      >
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);

    expect(screen.getByLabelText("Host")).toHaveValue("");
    expect(screen.getByRole("option", { name: "host-a" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "host-b" })).toBeInTheDocument();
  });

  it("prompts to select a host when none is chosen", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvents>);
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);

    expect(screen.getByText("Select a host to load its timeline.")).toBeInTheDocument();
  });

  it("forwards the selected host and time range to useSystemStory", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a")] }) as ReturnType<typeof hooks.useEvents>
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "host-a" } });
    fireEvent.change(screen.getByLabelText("Since (nanoseconds)"), { target: { value: "1000" } });
    fireEvent.change(screen.getByLabelText("Until (nanoseconds)"), { target: { value: "2000" } });

    expect(hooks.useSystemStory).toHaveBeenLastCalledWith("host-a", { since: 1000, until: 2000 });
  });

  it("renders events chronologically with a category badge", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ data: [sensorHealthEvent("host-a")] }) as ReturnType<typeof hooks.useEvents>
    );
    vi.mocked(hooks.useSystemStory).mockReturnValue(
      mockQueryResult({
        data: {
          events: [
            { event_id: "e2", event_type: "FILE_WRITE", timestamp: 2000, host: { host_id: "host-a", hostname: "h" }, category: "FILE", event_data: {} },
            { event_id: "e1", event_type: "PROCESS_EXEC", timestamp: 1000, host: { host_id: "host-a", hostname: "h" }, category: "PROCESS", event_data: {} },
          ],
          alerts: [],
        },
      }) as ReturnType<typeof hooks.useSystemStory>
    );

    render(<Timeline />);
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "host-a" } });

    const items = screen.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("PROCESS");
    expect(items[0]).toHaveTextContent("PROCESS_EXEC");
    expect(items[1]).toHaveTextContent("FILE");
    expect(items[1]).toHaveTextContent("FILE_WRITE");
  });

  it("applies the last-1-hour quick-select to the since field", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvents>);
    vi.mocked(hooks.useSystemStory).mockReturnValue(mockQueryResult({}) as ReturnType<typeof hooks.useSystemStory>);

    render(<Timeline />);
    fireEvent.click(screen.getByText("Last 1 hour"));

    expect(screen.getByLabelText("Since (nanoseconds)")).not.toHaveValue("");
  });
});
