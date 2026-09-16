import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { ContainerDetailScreen } from "./ContainerDetailScreen";

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

function renderAt(containerId: string) {
  return render(
    <MemoryRouter initialEntries={[`/containers/${containerId}`]}>
      <Routes>
        <Route path="/containers/:containerId" element={<ContainerDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ContainerDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("writes the CONTAINER key to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useContainerStory>
    );
    const { unmount } = renderAt("abc123");

    expect(useUiStore.getState().selectedEntity).toBe("CONTAINER:abc123");

    unmount();
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useContainerStory>
    );
    renderAt("abc123");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("explicitly writes the CONTAINER key when the pivot link is clicked", () => {
    vi.mocked(hooks.useContainerStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useContainerStory>
    );
    renderAt("abc123");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("CONTAINER:abc123");
  });
});
