import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as liveEvents from "../../api/liveEvents";
import { LiveEvents } from "./LiveEvents";

vi.mock("../../api/liveEvents");

function mockResult(
  overrides: Partial<ReturnType<typeof liveEvents.useLiveEvents>> = {}
): ReturnType<typeof liveEvents.useLiveEvents> {
  return {
    events: [],
    connectionState: "connecting",
    paused: false,
    setPaused: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  };
}

describe("LiveEvents", () => {
  it("shows the connection state", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ connectionState: "live" }));
    render(<LiveEvents />);
    expect(screen.getByRole("status")).toHaveTextContent("Live");
  });

  it("shows a message when there are no events yet", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult());
    render(<LiveEvents />);
    expect(screen.getByText("No events yet.")).toBeInTheDocument();
  });

  it("renders received events in a table", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(
      mockResult({
        events: [
          {
            event_id: "e1",
            event_type: "PROCESS_EXEC",
            timestamp: 1000,
            host: { host_id: "h1", hostname: "host-one" },
            event_data: {},
          },
        ],
      })
    );
    render(<LiveEvents />);
    expect(screen.getByText("PROCESS_EXEC")).toBeInTheDocument();
    expect(screen.getByText("host-one")).toBeInTheDocument();
  });

  it("calls setPaused(true) when Pause is clicked", () => {
    const setPaused = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ setPaused }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    expect(setPaused).toHaveBeenCalledWith(true);
  });

  it("shows Resume and calls setPaused(false) when already paused", () => {
    const setPaused = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ paused: true, setPaused }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(setPaused).toHaveBeenCalledWith(false);
  });

  it("calls clear when Clear is clicked", () => {
    const clear = vi.fn();
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult({ clear }));
    render(<LiveEvents />);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(clear).toHaveBeenCalled();
  });

  it("applying a Host ID filter re-invokes useLiveEvents with that filter", () => {
    vi.mocked(liveEvents.useLiveEvents).mockReturnValue(mockResult());
    render(<LiveEvents />);
    fireEvent.change(screen.getByLabelText("Host ID"), { target: { value: "host-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filter" }));
    expect(liveEvents.useLiveEvents).toHaveBeenLastCalledWith({ hostId: "host-1" });
  });
});
