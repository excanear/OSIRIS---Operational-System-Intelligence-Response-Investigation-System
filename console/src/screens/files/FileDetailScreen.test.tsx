import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { FileDetailScreen } from "./FileDetailScreen";

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

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/files/:fileId" element={<FileDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("FileDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows a loading state", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");
    expect(screen.getByText("Loading story…")).toBeInTheDocument();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("shows the Entity Graph pivot link and writes the composed FILE key when host_id is present", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100?host_id=h1");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");
    expect(useUiStore.getState().selectedEntity).toBe("FILE:h1:100:1");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("FILE:h1:100:1");
  });

  it("omits the Entity Graph pivot link when host_id is absent", () => {
    vi.mocked(hooks.useFileStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useFileStory>
    );
    renderAt("/files/1:100");

    expect(screen.queryByRole("link", { name: "View in Entity Graph" })).not.toBeInTheDocument();
  });
});
