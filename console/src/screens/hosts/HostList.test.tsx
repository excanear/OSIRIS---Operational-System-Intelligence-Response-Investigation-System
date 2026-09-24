import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { HostList } from "./HostList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useHosts>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <HostList />
    </MemoryRouter>
  );
}

describe("HostList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading hosts…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No hosts found.")).toBeInTheDocument();
  });

  it("renders a row per host, linking to Timeline pre-filtered by host", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "ubuntu-22.04", kernel_version: "5.15.0", agent_version: "0.1.0", enrolled_at: 500, last_seen: 1000, status: "ONLINE" },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "host-a" });
    expect(link).toHaveAttribute(
      "href",
      "/timeline?host=11111111-1111-1111-1111-111111111111"
    );
    expect(screen.getByText("ubuntu-22.04")).toBeInTheDocument();
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
  });

  it("renders an Agent version column and an Enrolled column", () => {
    const enrolledAtNs = 1_700_000_000_000_000_000;
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "ubuntu-22.04", kernel_version: "5.15.0", agent_version: "0.1.0", enrolled_at: enrolledAtNs, last_seen: 1000, status: "ONLINE" },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByRole("columnheader", { name: "Agent version" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Enrolled" })).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
    expect(screen.getByText(new Date(enrolledAtNs / 1_000_000).toLocaleString())).toBeInTheDocument();
  });
});
