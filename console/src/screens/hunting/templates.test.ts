import { describe, expect, it } from "vitest";
import { HUNT_TEMPLATES } from "./templates";

describe("HUNT_TEMPLATES", () => {
  it("has exactly the 3 templates the CLI also embeds, each non-empty", () => {
    expect(HUNT_TEMPLATES.map((template) => template.name)).toEqual([
      "network-download-then-write",
      "shell-wrote-file-to-web-root",
      "container-started-in-remote-session",
    ]);
    for (const template of HUNT_TEMPLATES) {
      expect(template.query.trim().length).toBeGreaterThan(0);
      expect(template.label.trim().length).toBeGreaterThan(0);
    }
  });

  it("includes the network-download-then-write template's known OQL content", () => {
    const template = HUNT_TEMPLATES.find((t) => t.name === "network-download-then-write");
    expect(template?.query).toContain("NETWORK_CONNECT");
  });
});
