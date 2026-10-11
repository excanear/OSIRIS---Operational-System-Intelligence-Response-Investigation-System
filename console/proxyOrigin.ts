// The API refuses a WebSocket handshake whose Origin differs from its Host
// (CSWSH guard in osiris-api stream.rs). Vite's proxy rewrites Host to the
// target (changeOrigin) but forwards the browser's Origin untouched, so Live
// Events got a 403 behind `vite dev` / `vite preview`. Rewrite Origin to the
// proxy target on upgrade requests so the same-site check sees a match.
interface UpgradeRequest {
  setHeader(name: string, value: string): void;
}
interface ProxyLike {
  on(event: "proxyReqWs", listener: (proxyReq: UpgradeRequest) => void): unknown;
}

export function rewriteWsOrigin(target: string): (proxy: ProxyLike) => void {
  return (proxy) => {
    proxy.on("proxyReqWs", (proxyReq) => proxyReq.setHeader("origin", target));
  };
}
