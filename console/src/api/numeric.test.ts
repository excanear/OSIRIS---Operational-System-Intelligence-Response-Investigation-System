import { describe, expect, it } from "vitest";
import { parseOptionalNumber } from "./numeric";

describe("parseOptionalNumber", () => {
  it("returns undefined for an empty string", () => {
    expect(parseOptionalNumber("")).toBeUndefined();
  });

  it("returns the parsed number for a valid number string", () => {
    expect(parseOptionalNumber("42")).toBe(42);
  });

  it("returns undefined for a non-numeric string", () => {
    expect(parseOptionalNumber("abc")).toBeUndefined();
  });

  it("returns undefined for a whitespace-only string", () => {
    expect(parseOptionalNumber("   ")).toBeUndefined();
  });
});
