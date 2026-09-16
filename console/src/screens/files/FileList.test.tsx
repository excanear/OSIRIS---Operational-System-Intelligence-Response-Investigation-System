import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { FileList } from "./FileList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useFiles>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <FileList />
    </MemoryRouter>
  );
}

describe("FileList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading files…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ isError: true, error: new Error("network down") }));
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No files found.")).toBeInTheDocument();
  });

  it("renders a row per file, linking to its detail route with host_id in the query string", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(
      mockQueryResult({
        data: [
          { file_id: "1:100", path: "/etc/passwd", host_id: "h1", hostname: "host-a", last_event_type: "FILE_WRITE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    const link = screen.getByRole("link", { name: "/etc/passwd" });
    expect(link).toHaveAttribute("href", "/files/1%3A100?host_id=h1");
    expect(screen.getByText("host-a")).toBeInTheDocument();
    expect(screen.getByText("FILE_WRITE")).toBeInTheDocument();
  });

  it("filters rows by path text", () => {
    vi.mocked(hooks.useFiles).mockReturnValue(
      mockQueryResult({
        data: [
          { file_id: "1:100", path: "/etc/passwd", host_id: "h1", hostname: "host-a", last_event_type: "FILE_WRITE", timestamp: 1000 },
          { file_id: "1:200", path: "/tmp/x", host_id: "h1", hostname: "host-a", last_event_type: "FILE_CREATE", timestamp: 1000 },
        ],
      })
    );
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Filter by path"), { target: { value: "passwd" } });

    expect(screen.getByText("/etc/passwd")).toBeInTheDocument();
    expect(screen.queryByText("/tmp/x")).not.toBeInTheDocument();
  });
});
