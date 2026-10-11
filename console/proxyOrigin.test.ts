import { describe, expect, it, vi } from "vitest";
import { consoleOrigins, rewriteWsOrigin } from "./proxyOrigin";

const TARGET = "http://127.0.0.1:8080";
const OWN = ["http://127.0.0.1:4173", "http://localhost:5173"];

type Listener = (
  proxyReq: { setHeader: (n: string, v: string) => void },
  req: { headers: Record<string, string | string[] | undefined> },
) => void;

function upgrade(origin: string | undefined) {
  let listener: Listener | undefined;
  const proxy = { on: (_event: "proxyReqWs", l: Listener) => void (listener = l) };
  rewriteWsOrigin(TARGET, OWN)(proxy as never);
  const setHeader = vi.fn();
  listener?.({ setHeader }, { headers: origin === undefined ? {} : { origin } });
  return setHeader;
}

describe("rewriteWsOrigin", () => {
  it("rewrites the Console's own origin to the proxy target", () => {
    expect(upgrade("http://127.0.0.1:4173")).toHaveBeenCalledWith("origin", TARGET);
    expect(upgrade("http://localhost:5173")).toHaveBeenCalledWith("origin", TARGET);
  });

  it("leaves a foreign origin untouched so the API rejects it", () => {
    expect(upgrade("https://evil.example")).not.toHaveBeenCalled();
    expect(upgrade("http://127.0.0.1:9999")).not.toHaveBeenCalled();
  });

  it("leaves a missing origin untouched", () => {
    expect(upgrade(undefined)).not.toHaveBeenCalled();
  });
});

describe("consoleOrigins", () => {
  it("covers the loopback names on every port", () => {
    expect(consoleOrigins([4173])).toEqual([
      "http://127.0.0.1:4173",
      "http://localhost:4173",
      "http://[::1]:4173",
    ]);
  });
});
