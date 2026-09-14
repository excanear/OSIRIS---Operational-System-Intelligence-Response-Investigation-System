import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ThreatHunting } from "./ThreatHunting";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useEvents>;
}

describe("ThreatHunting", () => {
  it("does not run a query before Run is clicked", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);
    expect(hooks.useEvents).toHaveBeenLastCalledWith(undefined, expect.objectContaining({ enabled: false }));
  });

  it("disables Run while the query textarea is empty", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);
    expect(screen.getByText("Run")).toBeDisabled();
  });

  it("selecting a template fills the textarea with its content", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("Template"), { target: { value: "network-download-then-write" } });

    expect(screen.getByLabelText("OQL query")).toHaveValue('event_type = "NETWORK_CONNECT" OR event_type = "FILE_WRITE"');
  });

  it("runs the typed query and enables useEvents with q set", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockQueryResult({}));
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: 'event_type = "FILE_WRITE"' } });
    fireEvent.click(screen.getByText("Run"));

    expect(hooks.useEvents).toHaveBeenLastCalledWith(
      undefined,
      expect.objectContaining({ q: 'event_type = "FILE_WRITE"', enabled: true })
    );
  });

  it("renders results once the query has run", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({
        data: [
          { event_id: "e1", event_type: "FILE_WRITE", timestamp: 1000, host: { host_id: "h1", hostname: "host-a" }, event_data: {} },
        ],
      })
    );
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: 'event_type = "FILE_WRITE"' } });
    fireEvent.click(screen.getByText("Run"));

    expect(screen.getByText("FILE_WRITE")).toBeInTheDocument();
    expect(screen.getByText("host-a")).toBeInTheDocument();
  });

  it("shows a query error via ApiError's surfaced message", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("GET /events failed with status 400: unexpected token") })
    );
    render(<ThreatHunting />);

    fireEvent.change(screen.getByLabelText("OQL query"), { target: { value: "not valid oql" } });
    fireEvent.click(screen.getByText("Run"));

    expect(screen.getByRole("alert")).toHaveTextContent("unexpected token");
  });
});
