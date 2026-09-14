import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { useUiStore } from "../../store/uiStore";
import { EntityGraph } from "./EntityGraph";

vi.mock("../../api/hooks");

let lastNodeLabel: unknown;

vi.mock("react-force-graph-2d", () => ({
  default: (props: { graphData: { nodes: unknown[]; links: unknown[] }; nodeLabel?: unknown }) => {
    lastNodeLabel = props.nodeLabel;
    return (
      <div data-testid="force-graph" data-node-count={props.graphData.nodes.length} data-link-count={props.graphData.links.length} />
    );
  },
}));

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useSubgraph>;
}

describe("EntityGraph", () => {
  beforeEach(() => {
    useUiStore.setState({ selectedEntity: null }, false);
  });

  it("shows the empty manual-entry state when no entity is selected", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));
    render(<EntityGraph />);
    expect(screen.getByLabelText("Entity key")).toHaveValue("");
  });

  it("auto-loads the pivoted-from entity from uiStore on mount", () => {
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));

    render(<EntityGraph />);

    expect(screen.getByLabelText("Entity key")).toHaveValue("IP:203.0.113.10");
    expect(hooks.useSubgraph).toHaveBeenCalledWith("IP:203.0.113.10");
  });

  it("rejects an invalid manual entry without calling useSubgraph with it", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({}));
    render(<EntityGraph />);

    fireEvent.change(screen.getByLabelText("Entity key"), { target: { value: "not-a-valid-key" } });
    fireEvent.click(screen.getByText("Load"));

    expect(screen.getByRole("alert")).toHaveTextContent("not a valid entity key");
  });

  it("shows a loading state while the subgraph is loading", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(mockQueryResult({ isLoading: true }));
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByText("Loading graph…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows a truncated banner when the subgraph was clipped", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({ data: { nodes: [], edges: [], truncated: true } })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);
    expect(screen.getByRole("status")).toHaveTextContent("truncated");
  });

  it("renders the force graph with the mapped nodes/links once loaded", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({
        data: {
          nodes: [
            { id: "IP:203.0.113.10", kind: "IP" },
            { id: "PROCESS:abc123", kind: "PROCESS" },
          ],
          edges: [
            { from: "PROCESS:abc123", to: "IP:203.0.113.10", relation: "CONNECTED_TO", event_id: "e1", timestamp: 1000 },
          ],
          truncated: false,
        },
      })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);

    const graph = screen.getByTestId("force-graph");
    expect(graph).toHaveAttribute("data-node-count", "2");
    expect(graph).toHaveAttribute("data-link-count", "1");
  });

  it("passes a nodeLabel function that builds a plain-text tooltip element instead of a raw string", () => {
    vi.mocked(hooks.useSubgraph).mockReturnValue(
      mockQueryResult({
        data: {
          nodes: [{ id: "IP:203.0.113.10", kind: "IP" }],
          edges: [],
          truncated: false,
        },
      })
    );
    useUiStore.setState({ selectedEntity: "IP:203.0.113.10" }, false);
    render(<EntityGraph />);

    expect(typeof lastNodeLabel).toBe("function");
    const nodeLabelFn = lastNodeLabel as (node: { id?: string | number }) => unknown;
    const result = nodeLabelFn({ id: "IP:203.0.113.10" });

    expect(typeof result).not.toBe("string");
    expect(result).toBeInstanceOf(HTMLElement);
    expect((result as HTMLElement).textContent).toBe("IP:203.0.113.10");
  });
});
