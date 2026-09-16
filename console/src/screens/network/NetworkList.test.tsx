import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { NetworkList } from "./NetworkList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useNetwork>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <NetworkList />
    </MemoryRouter>
  );
}

describe("NetworkList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading network connections…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No network connections found.")).toBeInTheDocument();
  });

  it("renders a row per destination, linking to its detail route", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "h1", hostname: "host-a", dst_ip: "93.184.216.34", dst_port: 443, proto: "tcp", last_event_type: "NETWORK_CLOSE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "93.184.216.34:443" });
    expect(link).toHaveAttribute("href", "/network/93.184.216.34");
    expect(screen.getByText("tcp")).toBeInTheDocument();
    expect(screen.getByText("host-a")).toBeInTheDocument();
  });

  it("filters rows by destination text", () => {
    vi.mocked(hooks.useNetwork).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "h1", hostname: "host-a", dst_ip: "93.184.216.34", dst_port: 443, proto: "tcp", last_event_type: "NETWORK_CLOSE", timestamp: 1000 },
          { host_id: "h1", hostname: "host-a", dst_ip: "10.0.0.9", dst_port: 22, proto: "tcp", last_event_type: "NETWORK_CONNECT", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by destination"), { target: { value: "93.184" } });

    expect(screen.getByText("93.184.216.34:443")).toBeInTheDocument();
    expect(screen.queryByText("10.0.0.9:22")).not.toBeInTheDocument();
  });
});
