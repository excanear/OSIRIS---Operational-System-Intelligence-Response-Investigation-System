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
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "host-a", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 1000, status: "ONLINE" },
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

  it("renders a Cloud column with provider and region, and a dash when absent", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "11111111-1111-1111-1111-111111111111", hostname: "cloud-host", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 1000, status: "ONLINE", cloud_provider: "aws", cloud_instance_id: "i-0abc", cloud_region: "us-east-1" },
          { host_id: "22222222-2222-2222-2222-222222222222", hostname: "onprem-host", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 900, status: "STALE", cloud_provider: null, cloud_instance_id: null, cloud_region: null },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByRole("columnheader", { name: "Cloud" })).toBeInTheDocument();
    expect(screen.getByText("aws / us-east-1")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("renders just the provider when the cloud region is absent", () => {
    vi.mocked(hooks.useHosts).mockReturnValue(
      mockQueryResult({
        data: [
          { host_id: "33333333-3333-3333-3333-333333333333", hostname: "azure-host", distro: "ubuntu-22.04", kernel_version: "5.15.0", last_seen: 800, status: "ONLINE", cloud_provider: "azure", cloud_instance_id: null, cloud_region: null },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByText("azure")).toBeInTheDocument();
  });
});
