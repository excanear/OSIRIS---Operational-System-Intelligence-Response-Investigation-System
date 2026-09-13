import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ProcessList } from "./ProcessList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useProcesses>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <ProcessList />
    </MemoryRouter>
  );
}

describe("ProcessList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading processes…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No processes found.")).toBeInTheDocument();
  });

  it("renders a row per process, linking to its detail route", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({
        data: [{ process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 }],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "/usr/bin/curl" });
    expect(link).toHaveAttribute("href", "/processes/abc123");
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("filters rows by exe_path text", () => {
    vi.mocked(hooks.useProcesses).mockReturnValue(
      mockQueryResult({
        data: [
          { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", timestamp: 1000 },
          { process_key: "def456", pid: 43, exe_path: "/usr/bin/wget", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by exe path"), { target: { value: "curl" } });

    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.queryByText("/usr/bin/wget")).not.toBeInTheDocument();
  });
});
