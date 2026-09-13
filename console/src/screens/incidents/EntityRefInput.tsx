import type { EntityRef } from "../../api/types";

export interface EntityRefRow {
  kind: "IP" | "DOMAIN";
  value: string;
}

export interface EntityRefInputProps {
  rows: EntityRefRow[];
  onChange: (rows: EntityRefRow[]) => void;
}

export function EntityRefInput({ rows, onChange }: EntityRefInputProps) {
  function updateRow(index: number, patch: Partial<EntityRefRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  function removeRow(index: number) {
    onChange(rows.filter((_, i) => i !== index));
  }

  function addRow() {
    onChange([...rows, { kind: "IP", value: "" }]);
  }

  return (
    <fieldset>
      <legend>Entities</legend>
      {rows.map((row, index) => (
        <div key={index}>
          <select
            aria-label={`Entity ${index + 1} kind`}
            value={row.kind}
            onChange={(event) => updateRow(index, { kind: event.target.value as "IP" | "DOMAIN" })}
          >
            <option value="IP">IP</option>
            <option value="DOMAIN">Domain</option>
          </select>
          <input
            type="text"
            aria-label={`Entity ${index + 1} value`}
            value={row.value}
            onChange={(event) => updateRow(index, { value: event.target.value })}
          />
          <button type="button" onClick={() => removeRow(index)}>
            Remove
          </button>
        </div>
      ))}
      <button type="button" onClick={addRow}>
        Add entity
      </button>
    </fieldset>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function entityRefRowsToEntityRefs(rows: EntityRefRow[]): EntityRef[] {
  return rows
    .filter((row) => row.value.trim().length > 0)
    .map((row) =>
      row.kind === "IP"
        ? { kind: "IP" as const, addr: row.value.trim() }
        : { kind: "DOMAIN" as const, name: row.value.trim() }
    );
}
