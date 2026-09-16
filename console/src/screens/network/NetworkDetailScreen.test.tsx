import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { NetworkDetailScreen } from "./NetworkDetailScreen";

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

function renderAt(ip: string) {
  return render(
    <MemoryRouter initialEntries={[`/network/${ip}`]}>
      <Routes>
        <Route path="/network/:ip" element={<NetworkDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("NetworkDetailScreen", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("writes the IP key to uiStore.selectedEntity on mount and clears it on unmount", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useNetworkStory>
    );
    const { unmount } = renderAt("93.184.216.34");

    expect(useUiStore.getState().selectedEntity).toBe("IP:93.184.216.34");

    unmount();
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("renders the story's alerts and events once loaded", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
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
      }) as ReturnType<typeof hooks.useNetworkStory>
    );
    renderAt("93.184.216.34");

    expect(screen.getByText("Related alerts (1)")).toBeInTheDocument();
    expect(screen.getByText("rule_a: suspicious")).toBeInTheDocument();
  });

  it("explicitly writes the IP key when the pivot link is clicked", () => {
    vi.mocked(hooks.useNetworkStory).mockReturnValue(
      mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useNetworkStory>
    );
    renderAt("93.184.216.34");

    const link = screen.getByRole("link", { name: "View in Entity Graph" });
    expect(link).toHaveAttribute("href", "/graph");

    link.click();
    expect(useUiStore.getState().selectedEntity).toBe("IP:93.184.216.34");
  });
});
