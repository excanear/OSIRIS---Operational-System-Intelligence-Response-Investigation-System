import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { ProcessDetailScreen } from "./ProcessDetailScreen";

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

function renderAt(processKey: string) {
  return render(
    <MemoryRouter initialEntries={[`/processes/${processKey}`]}>
      <Routes>
        <Route path="/processes/:processKey" element={<ProcessDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ProcessDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows loading states for both process and story", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");
    expect(screen.getByText("Loading process…")).toBeInTheDocument();
    expect(screen.getByText("Loading story…")).toBeInTheDocument();
  });

  it("shows the process's children and the story's alerts once loaded", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(
      mockQueryResult({
        data: {
          process: {
            event_id: "e1",
            event_type: "PROCESS_EXEC",
            timestamp: 1000,
            host: { host_id: "h1", hostname: "h" },
            process: { process_key: "abc123", pid: 42, exe_path: "/usr/bin/curl", cmdline: [], exe_hash: null, start_time_mono: 1 },
            event_data: {},
          },
          children: [
            {
              event_id: "e2",
              event_type: "PROCESS_EXEC",
              timestamp: 2000,
              host: { host_id: "h1", hostname: "h" },
              process: { process_key: "def456", pid: 43, exe_path: "/usr/bin/child", cmdline: [], exe_hash: null, start_time_mono: 2 },
              event_data: {},
            },
          ],
        },
      }) as ReturnType<typeof hooks.useProcess>
    );
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({
        data: {
          events: [],
          alerts: [
            {
              alert_id: "a1",
              rule_id: "rule_a",
              rule_version: 1,
              rule_content_hash: "hash",
              severity: "HIGH",
              status: "OPEN",
              timestamp: 1000,
              host_id: "h1",
              reasons: ["suspicious"],
              evidence: ["e1"],
            },
          ],
        },
      }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");

    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.getByText("Children (1)")).toBeInTheDocument();
    expect(screen.getByText("/usr/bin/child")).toBeInTheDocument();
    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("writes the processKey to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    const { unmount } = renderAt("abc123");

    expect(useUiStore.getState().selectedEntity).toBe("PROCESS:abc123");

    unmount();

    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("renders a link to view the process in Entity Graph", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");
  });

  it("explicitly writes the processKey to uiStore.selectedEntity when the pivot link is clicked", () => {
    vi.mocked(hooks.useProcess).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcess>);
    vi.mocked(hooks.useProcessStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useProcessStory>
    );
    renderAt("abc123");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });

    link.click();

    expect(useUiStore.getState().selectedEntity).toBe("PROCESS:abc123");
  });
});
