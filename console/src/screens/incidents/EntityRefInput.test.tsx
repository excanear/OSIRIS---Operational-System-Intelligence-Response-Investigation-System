import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { EntityRefInput, entityRefRowsToEntityRefs, type EntityRefRow } from "./EntityRefInput";

describe("entityRefRowsToEntityRefs", () => {
  it("converts an IP row to an EntityRef", () => {
    const rows: EntityRefRow[] = [{ kind: "IP", value: "203.0.113.10" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("converts a DOMAIN row to an EntityRef", () => {
    const rows: EntityRefRow[] = [{ kind: "DOMAIN", value: "evil.example" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "DOMAIN", name: "evil.example" }]);
  });

  it("drops rows with a blank value", () => {
    const rows: EntityRefRow[] = [{ kind: "IP", value: "  " }, { kind: "IP", value: "203.0.113.10" }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "IP", addr: "203.0.113.10" }]);
  });

  it("trims whitespace from the value", () => {
    const rows: EntityRefRow[] = [{ kind: "DOMAIN", value: "  evil.example  " }];
    expect(entityRefRowsToEntityRefs(rows)).toEqual([{ kind: "DOMAIN", name: "evil.example" }]);
  });
});

describe("EntityRefInput", () => {
  it("renders one kind selector and value input per row", () => {
    render(<EntityRefInput rows={[{ kind: "IP", value: "" }]} onChange={vi.fn()} />);
    expect(screen.getByLabelText("Entity 1 kind")).toBeInTheDocument();
    expect(screen.getByLabelText("Entity 1 value")).toBeInTheDocument();
  });

  it("calls onChange with an added row when Add entity is clicked", () => {
    const onChange = vi.fn();
    render(<EntityRefInput rows={[{ kind: "IP", value: "" }]} onChange={onChange} />);
    screen.getByText("Add entity").click();
    expect(onChange).toHaveBeenCalledWith([
      { kind: "IP", value: "" },
      { kind: "IP", value: "" },
    ]);
  });

  it("calls onChange with the row removed when Remove is clicked", () => {
    const onChange = vi.fn();
    render(
      <EntityRefInput
        rows={[{ kind: "IP", value: "a" }, { kind: "DOMAIN", value: "b" }]}
        onChange={onChange}
      />
    );
    screen.getAllByText("Remove")[0].click();
    expect(onChange).toHaveBeenCalledWith([{ kind: "DOMAIN", value: "b" }]);
  });
});
