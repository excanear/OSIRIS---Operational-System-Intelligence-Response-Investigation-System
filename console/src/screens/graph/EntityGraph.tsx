import { useEffect, useState, type ComponentProps, type FormEvent } from "react";
import ForceGraph2D, { type NodeObject } from "react-force-graph-2d";
import { useSubgraph } from "../../api/hooks";
import { isValidEntityKey } from "../../api/entityKey";
import { useUiStore } from "../../store/uiStore";

// react-force-graph-2d's own .d.ts types a function nodeLabel's return as
// React.ReactHTMLElement<HTMLElement> (a React element), but its runtime
// (the float-tooltip dependency) actually expects and appends a real DOM
// HTMLElement directly — the .d.ts is inaccurate here, so the cast below via
// `unknown` is required to satisfy tsc while returning an actual HTMLElement.
type NodeLabelProp = ComponentProps<typeof ForceGraph2D>["nodeLabel"];

export function EntityGraph() {
  const selectedEntity = useUiStore((state) => state.selectedEntity);
  const [entityInput, setEntityInput] = useState(selectedEntity ?? "");
  const [activeEntity, setActiveEntity] = useState(selectedEntity ?? "");
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (selectedEntity) {
      setEntityInput(selectedEntity);
      setActiveEntity(selectedEntity);
    }
    // Reacts only to a change in the pivoted-from entity — deliberately
    // omits entityInput/activeEntity from deps so typing in the manual
    // field is never clobbered by a stale selectedEntity re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEntity]);

  const subgraph = useSubgraph(activeEntity);

  function handleLoad(event: FormEvent) {
    event.preventDefault();
    if (!isValidEntityKey(entityInput)) {
      setValidationError(`"${entityInput}" is not a valid entity key (expected KIND:value)`);
      return;
    }
    setValidationError(null);
    setActiveEntity(entityInput);
  }

  const graphData = subgraph.data
    ? {
        nodes: subgraph.data.nodes,
        links: subgraph.data.edges.map((edge) => ({ ...edge, source: edge.from, target: edge.to })),
      }
    : { nodes: [], links: [] };

  return (
    <div>
      <h1>Entity Graph</h1>
      <form onSubmit={handleLoad}>
        <input
          type="text"
          aria-label="Entity key"
          placeholder="KIND:value, e.g. IP:203.0.113.10"
          value={entityInput}
          onChange={(event) => setEntityInput(event.target.value)}
        />
        <button type="submit">Load</button>
      </form>
      {validationError && <p role="alert">{validationError}</p>}
      {activeEntity && subgraph.isLoading && <p>Loading graph…</p>}
      {activeEntity && subgraph.isError && (
        <p role="alert">Failed to load graph: {(subgraph.error as Error).message}</p>
      )}
      {subgraph.data?.truncated && (
        <p role="status">Graph truncated — not all reachable nodes are shown.</p>
      )}
      {activeEntity && subgraph.data && (
        <div style={{ height: 600 }}>
          <ForceGraph2D
            graphData={graphData}
            nodeId="id"
            nodeLabel={
              // Build a plain-text tooltip element instead of returning a raw
              // string: react-force-graph-2d's float-tooltip dependency
              // .html()'s a string nodeLabel (innerHTML), and node.id here is
              // a telemetry-derived EntityRef::storage_key() that a
              // compromised monitored host could poison with markup — a
              // stored-XSS vector. An HTMLElement return is appended via safe
              // DOM APIs instead.
              ((node: NodeObject) => {
                const el = document.createElement("div");
                el.textContent = String(node.id);
                return el;
              }) as unknown as NodeLabelProp
            }
            nodeAutoColorBy="kind"
          />
        </div>
      )}
    </div>
  );
}
