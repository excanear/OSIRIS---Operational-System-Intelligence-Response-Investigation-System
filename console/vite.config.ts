/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { rewriteWsOrigin } from "./proxyOrigin";

export default defineConfig({
  plugins: [react()],
  server: {
    // Vite's dev server (and Vitest, which shares this config) refuses to
    // serve files outside the project root by default. The three saved
    // hunt templates live in the repo's own `hunts/` directory (one level
    // up), the same source the CLI embeds via `include_str!` — this
    // widens the allowlist to include it, not the whole filesystem.
    fs: {
      allow: [".."],
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
        // Live Events' WebSocket upgrade (GET /api/v1/stream/events)
        // needs this explicitly — Vite's dev proxy does not forward
        // WebSocket upgrades by default.
        ws: true,
        configure: rewriteWsOrigin("http://127.0.0.1:8080"),
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    exclude: ["e2e/**", "node_modules/**"],
  },
});
