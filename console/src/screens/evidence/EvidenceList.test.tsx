import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { EvidenceList } from "./EvidenceList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useAllEvidence>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <EvidenceList />
    </MemoryRouter>
  );
}

describe("EvidenceList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(mockQueryResult({ isLoading: true }));
    renderWithRouter();
    expect(screen.getByText("Loading evidence…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    renderWithRouter();
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(mockQueryResult({ data: [] }));
    renderWithRouter();
    expect(screen.getByText("No evidence recorded.")).toBeInTheDocument();
  });

  it("renders a row per evidence record with a linked incident", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence: {
              evidence_id: "e1",
              source: "MANUAL_UPLOAD",
              timestamp: 1000,
              integrity: { hash: "abc123", immutable_since: 1000 },
              relationships: [],
              supersedes: null,
            },
            incident_ids: ["i1"],
          },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByText("MANUAL_UPLOAD")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "i1" });
    expect(link).toHaveAttribute("href", "/incidents/i1");
  });

  it("shows a dash for evidence with no linked incident", () => {
    vi.mocked(hooks.useAllEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence: {
              evidence_id: "e1",
              source: "EVENT_CAPTURE",
              timestamp: 1000,
              integrity: { hash: "abc123", immutable_since: 1000 },
              relationships: [],
              supersedes: null,
            },
            incident_ids: [],
          },
        ],
      })
    );
    renderWithRouter();

    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
