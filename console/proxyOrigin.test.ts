import { describe, expect, it, vi } from "vitest";
import { rewriteWsOrigin } from "./proxyOrigin";

describe("rewriteWsOrigin", () => {
  it("sets the upgrade request's Origin to the proxy target", () => {
    let listener: ((req: { setHeader: (n: string, v: string) => void }) => void) | undefined;
    const proxy = { on: (_event: "proxyReqWs", l: typeof listener) => void (listener = l) };
    rewriteWsOrigin("http://127.0.0.1:8080")(proxy as never);
    const setHeader = vi.fn();
    listener?.({ setHeader });
    expect(setHeader).toHaveBeenCalledWith("origin", "http://127.0.0.1:8080");
  });
});
