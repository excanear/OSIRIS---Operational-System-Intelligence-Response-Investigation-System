// The API refuses a WebSocket handshake whose Origin differs from its Host
// (CSWSH guard in osiris-api stream.rs). Vite's proxy rewrites Host to the
// target (changeOrigin) but forwards the browser's Origin untouched, so Live
// Events got a 403 behind `vite dev` / `vite preview`. Rewrite Origin to the
// proxy target on upgrade requests, but only when the browser's Origin is the
// Console's own dev/preview origin: any other page's Origin is forwarded as-is
// so the API's guard still rejects it.
interface UpgradeRequest {
  setHeader(name: string, value: string): void;
}
interface IncomingRequest {
  headers: Record<string, string | string[] | undefined>;
}
interface ProxyLike {
  on(event: "proxyReqWs", listener: (proxyReq: UpgradeRequest, req: IncomingRequest) => void): unknown;
}

// Origins a browser uses for the Console served by Vite on the given ports.
export function consoleOrigins(ports: number[]): string[] {
  return ports.flatMap((port) => ["127.0.0.1", "localhost", "[::1]"].map((host) => `http://${host}:${port}`));
}

export function rewriteWsOrigin(target: string, ownOrigins: string[]): (proxy: ProxyLike) => void {
  const own = new Set(ownOrigins);
  return (proxy) => {
    proxy.on("proxyReqWs", (proxyReq, req) => {
      const origin = req.headers.origin;
      if (typeof origin === "string" && own.has(origin)) proxyReq.setHeader("origin", target);
    });
  };
}
