/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

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
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
  },
});
