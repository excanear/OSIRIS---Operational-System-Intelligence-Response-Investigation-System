import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ContainerList } from "./ContainerList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useContainers>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <ContainerList />
    </MemoryRouter>
  );
}

describe("ContainerList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading containers…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No containers found.")).toBeInTheDocument();
  });

  it("renders a row per container, linking to its detail route", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [{ container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000 }],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "abc123" });
    expect(link).toHaveAttribute("href", "/containers/abc123");
    expect(screen.getByText("nginx:latest")).toBeInTheDocument();
    expect(screen.getByText("RUNNING")).toBeInTheDocument();
  });

  it("filters rows by image or container_id text", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [
          { container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000 },
          { container_id: "def456", host_id: "h1", hostname: "host-a", image: "redis:7", status: "STOPPED", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by image or container ID"), { target: { value: "nginx" } });

    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.queryByText("def456")).not.toBeInTheDocument();
  });

  it("renders a Pod column as namespace/pod, and a dash when there is no pod", () => {
    vi.mocked(hooks.useContainers).mockReturnValue(
      mockQueryResult({
        data: [
          { container_id: "abc123", host_id: "h1", hostname: "host-a", image: "nginx:latest", status: "RUNNING", timestamp: 1000, pod_name: "web-0", pod_namespace: "prod" },
          { container_id: "def456", host_id: "h1", hostname: "host-a", image: "redis:7", status: "RUNNING", timestamp: 900, pod_name: null, pod_namespace: null },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByRole("columnheader", { name: "Pod" })).toBeInTheDocument();
    expect(screen.getByText("prod/web-0")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
