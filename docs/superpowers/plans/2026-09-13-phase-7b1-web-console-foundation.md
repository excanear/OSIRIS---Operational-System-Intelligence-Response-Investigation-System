# Phase 7b-1: Web Console Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the OSIRIS Web Console (`console/`, a Vite+React+TypeScript SPA) with its app shell, a hand-written typed API client, and its first two working screens (Overview, Sensors), against the existing `osiris-api` surface with no backend endpoint changes.

**Architecture:** A pure SPA (no server-side rendering) fetches from the already-existing `osiris-api` REST endpoints via TanStack Query, with a fixed left-nav enumerating all 13 §16.3 screens (only Overview and Sensors functional; the rest show "coming soon"). A small `osiris-server` change adds a dev-only CORS layer so the Vite dev server (its own origin/port) can call the API. Cross-cutting UI state (selected entity, time range, filters) lives in a Zustand store created now, unused by this phase's two screens, so later phases (7b-2+) that need cross-screen selection sharing don't have to retrofit it.

**Tech Stack:** Vite, React 18, TypeScript 5, TanStack Query v5, Zustand, react-router-dom v6, Vitest + React Testing Library, ESLint + Prettier. Backend: `tower-http`'s `CorsLayer` added to `osiris-server`.

**Spec:** `docs/superpowers/specs/2026-09-13-phase-7b1-web-console-foundation-design.md`

## Global Constraints

- No backend endpoint is added, removed, or changed in behavior — this phase only adds a dev-only CORS layer to `osiris-server`. `osiris-api`'s handlers, `osiris-query`, `osiris-investigate`, and `osiris-evidence` are untouched.
- No auth/login — the Console calls the API unauthenticated, matching the rest of the system today (§14.3's RBAC is a separate future phase).
- The API client is hand-written TypeScript, not generated from an OpenAPI spec (no `utoipa`/`aide` work in this phase).
- No production static-asset serving is wired into `osiris-server` — dev only, via the Vite dev server's proxy.
- No Playwright/e2e — Vitest + React Testing Library only.
- Only Overview and Sensors are functional screens in this phase; the other 11 §16.3 screens render a shared "coming soon" placeholder and are non-interactive nav entries.
- Dark-first, information-dense, monospace-for-data-fields visual direction (§16.2) — no light theme, no card-heavy dashboard styling.
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` must stay green after the backend change; `npm run build`, `npm test`, and `npm run lint` must pass in `console/` after every frontend task.

---

### Task 1: Backend — document and test the SensorHealth wire shape

No code in `osiris-health` currently constructs and pushes an
`EventType::SensorHealth`/`AgentHealth` event into the pipeline (verified
by grep — the crate's `HealthAggregator`/`SensorHealth`/`HealthState`
types exist but are never wired into event emission). This task adds one
integration-style test to `osiris-api` that writes a `SensorHealth`
`CanonicalEvent` straight into `Storage` (bypassing the missing emission
path) and confirms `GET /api/v1/events?event_type=SENSOR_HEALTH` returns
it with the exact JSON shape the Console's Sensors screen (Task 8) will
parse. This is the authoritative fixture the frontend rollup tests must
match byte-for-byte.

**Files:**
- Modify: `crates/osiris-api/src/lib.rs` (add a fixture fn and a test to the existing `mod tests` block, around line 713-780)

**Interfaces:**
- Produces: the documented `event_data` shape for a `SensorHealth` event —
  ```json
  {
    "sensor_name": "<string>",
    "state": { "state": "HEALTHY" | "DEGRADED" | "FAILED", "last_error": "<string, only for DEGRADED/FAILED>" },
    "events_processed": <number>,
    "last_event_at": <number | null>
  }
  ```
  (the double-nested `state.state` comes from `osiris-health::SensorHealth`'s
  own field named `state: HealthState`, where `HealthState` is itself
  internally tagged `#[serde(tag = "state")]` — not a typo, verified by
  reading `crates/osiris-health/src/state.rs`). Task 8's TypeScript types
  and test fixtures must mirror this exactly.

- [ ] **Step 1: Write the failing test**

Add this function immediately before `fn sample_alert` (currently at
line 715 of `crates/osiris-api/src/lib.rs`):

```rust
    fn sensor_health_event(host_id: Uuid, sensor_name: &str, timestamp: u64) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: timestamp,
            event_type: EventType::SensorHealth,
            category: Category::System,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({
                "sensor_name": sensor_name,
                "state": {
                    "state": "FAILED",
                    "last_error": "eBPF load failure: verifier rejected program",
                },
                "events_processed": 42,
                "last_event_at": timestamp,
            }),
        }
    }
```

Add this test immediately before the existing
`events_endpoint_rejects_a_malformed_oql_query_string` test (currently at
line 780-781):

```rust
    #[tokio::test]
    async fn events_endpoint_filters_by_sensor_health_event_type() {
        let (_dir, storage) = test_storage();
        let host_id = Uuid::new_v4();
        storage
            .write(&sensor_health_event(host_id, "network", 5000))
            .unwrap();
        storage.write(&sample_event(100, None, 1000)).unwrap();

        let q = EventsQuery {
            event_type: Some("SENSOR_HEALTH".to_string()),
            since: None,
            until: None,
            limit: None,
            export: None,
            q: None,
        };
        let Json(events) = events_handler(State(storage), Query(q)).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::SensorHealth);
        assert_eq!(events[0].event_data["sensor_name"], "network");
        assert_eq!(events[0].event_data["state"]["state"], "FAILED");
        assert_eq!(
            events[0].event_data["state"]["last_error"],
            "eBPF load failure: verifier rejected program"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p osiris-api events_endpoint_filters_by_sensor_health_event_type`
Expected: FAIL to compile (`sensor_health_event` / test not yet added) — if you added both the fixture and the test in Step 1, this instead runs and should already PASS since no production code changes are needed. Confirm it compiles and passes.

- [ ] **Step 3: Run the full osiris-api test suite**

Run: `cargo test -p osiris-api`
Expected: PASS, all tests including the new one.

- [ ] **Step 4: Commit**

```bash
git add crates/osiris-api/src/lib.rs
git commit -m "test(api): pin the SensorHealth event wire shape the Console's Sensors screen will consume"
```

---

### Task 2: Backend — dev-only CORS layer on osiris-server

**Files:**
- Modify: `Cargo.toml` (workspace root — add `tower-http` and `tower` to `[workspace.dependencies]`)
- Modify: `crates/osiris-server/Cargo.toml` (add the two deps)
- Create: `crates/osiris-server/src/cors.rs`
- Modify: `crates/osiris-server/src/lib.rs` (register the new module)
- Modify: `crates/osiris-server/src/config.rs` (add `dev_cors: Option<bool>` field)
- Modify: `crates/osiris-server/src/main.rs` (apply the layer)

**Interfaces:**
- Produces: `pub fn apply_dev_cors(app: axum::Router, dev_cors: Option<bool>) -> axum::Router` in `osiris_server::cors`, re-exported as `osiris_server::apply_dev_cors`. `ServerConfig.dev_cors: Option<bool>`.

- [ ] **Step 1: Add workspace dependencies**

In `Cargo.toml` (workspace root), add these two lines inside the existing `[workspace.dependencies]` table (anywhere among the other entries):

```toml
tower = { version = "0.4", features = ["util"] }
tower-http = { version = "0.5", features = ["cors"] }
```

- [ ] **Step 2: Add them to osiris-server's Cargo.toml**

In `crates/osiris-server/Cargo.toml`, add to `[dependencies]`:

```toml
tower-http = { workspace = true }
```

Add a new `[dev-dependencies]` entry (the file has none yet other crates share — create the section):

```toml

[dev-dependencies]
tower = { workspace = true }
```

- [ ] **Step 3: Write the failing test**

Create `crates/osiris-server/src/cors.rs`:

```rust
use axum::Router;
use tower_http::cors::CorsLayer;

/// Wraps `app` in a permissive CORS layer only when `dev_cors` is
/// explicitly `Some(true)` (`ServerConfig::dev_cors`) — a missing or
/// `false` value leaves `app` untouched, so a production config that
/// never mentions `dev_cors` stays closed by default.
pub fn apply_dev_cors(app: Router, dev_cors: Option<bool>) -> Router {
    if dev_cors == Some(true) {
        app.layer(CorsLayer::permissive())
    } else {
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    #[tokio::test]
    async fn dev_cors_none_adds_no_allow_origin_header() {
        let app = apply_dev_cors(test_router(), None);
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn dev_cors_false_adds_no_allow_origin_header() {
        let app = apply_dev_cors(test_router(), Some(false));
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn dev_cors_true_sets_allow_origin_header() {
        let app = apply_dev_cors(test_router(), Some(true));
        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_some());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p osiris-server cors::`
Expected: FAIL to compile — `crates/osiris-server/src/cors.rs` isn't registered as a module yet.

- [ ] **Step 5: Register the module**

In `crates/osiris-server/src/lib.rs`, change:

```rust
pub mod config;
pub mod ingest;

pub use config::{ConfigError, ServerConfig};
pub use ingest::run_ingestion_loop;
```

to:

```rust
pub mod config;
pub mod cors;
pub mod ingest;

pub use config::{ConfigError, ServerConfig};
pub use cors::apply_dev_cors;
pub use ingest::run_ingestion_loop;
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p osiris-server cors::`
Expected: PASS (3 tests).

- [ ] **Step 7: Write the failing config test**

In `crates/osiris-server/src/config.rs`, add this test inside the existing `mod tests` block (after `loads_a_minimal_config_without_the_new_fields`):

```rust
    #[test]
    fn dev_cors_defaults_to_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.dev_cors, None);
    }

    #[test]
    fn dev_cors_parses_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.yaml");
        std::fs::write(
            &path,
            "db_path: /tmp/events.db\nspool_path: /tmp/spool.ndjson\nlisten_addr: 127.0.0.1:8080\nrules_dir: /etc/osiris/rules\ndev_cors: true\n",
        )
        .unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.dev_cors, Some(true));
    }
```

- [ ] **Step 8: Run the config tests to verify they fail**

Run: `cargo test -p osiris-server config::tests::dev_cors`
Expected: FAIL to compile — `ServerConfig` has no `dev_cors` field yet.

- [ ] **Step 9: Add the field**

In `crates/osiris-server/src/config.rs`, change the `ServerConfig` struct's last field:

```rust
    #[serde(default)]
    pub investigate_audit_log_path: Option<String>,
}
```

to:

```rust
    #[serde(default)]
    pub investigate_audit_log_path: Option<String>,
    /// Phase 7b-1: dev-only permissive CORS for the Console's Vite dev
    /// server (a different origin/port than osiris-server). `None`/`false`
    /// (the default for any config that doesn't mention it) leaves CORS
    /// disabled — this must never be enabled unconditionally in a way a
    /// production deployment could inherit by omission.
    #[serde(default)]
    pub dev_cors: Option<bool>,
}
```

- [ ] **Step 10: Run the config tests to verify they pass**

Run: `cargo test -p osiris-server config::`
Expected: PASS, all tests including the two new ones.

- [ ] **Step 11: Wire it into main.rs**

In `crates/osiris-server/src/main.rs`, change:

```rust
    let app = build_router(storage).merge(build_incident_evidence_router(incident_evidence_state));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

to:

```rust
    let app = osiris_server::apply_dev_cors(
        build_router(storage).merge(build_incident_evidence_router(incident_evidence_state)),
        config.dev_cors,
    );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

- [ ] **Step 12: Run the full workspace test suite and lint**

Run: `cargo test --workspace`
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 13: Commit**

```bash
git add Cargo.toml crates/osiris-server/Cargo.toml crates/osiris-server/src/cors.rs crates/osiris-server/src/lib.rs crates/osiris-server/src/config.rs crates/osiris-server/src/main.rs
git commit -m "feat(server): add a dev-only CORS layer for the Console's Vite dev server"
```

---

### Task 3: Console project scaffold (Vite + React + TypeScript + Vitest + ESLint + Prettier)

**Files:**
- Create: `console/package.json`
- Create: `console/tsconfig.json`
- Create: `console/tsconfig.node.json`
- Create: `console/vite.config.ts`
- Create: `console/vitest.setup.ts`
- Create: `console/index.html`
- Create: `console/.eslintrc.cjs`
- Create: `console/.prettierrc.json`
- Create: `console/.gitignore`
- Create: `console/src/index.css`
- Create: `console/src/main.tsx`
- Create: `console/src/App.tsx`
- Test: `console/src/App.test.tsx`

**Interfaces:**
- Produces: `export function App(): JSX.Element` from `console/src/App.tsx` — Tasks 6-8 will replace its body but keep this exported name/signature.

- [ ] **Step 1: Create package.json**

```json
{
  "name": "osiris-console",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "engines": {
    "node": ">=20"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "lint": "eslint . --ext .ts,.tsx"
  },
  "dependencies": {
    "@tanstack/react-query": "^5.59.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2",
    "zustand": "^4.5.5"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.5.0",
    "@testing-library/react": "^16.0.1",
    "@types/react": "^18.3.9",
    "@types/react-dom": "^18.3.0",
    "@typescript-eslint/eslint-plugin": "^8.6.0",
    "@typescript-eslint/parser": "^8.6.0",
    "@vitejs/plugin-react": "^4.3.1",
    "eslint": "^8.57.1",
    "eslint-plugin-react-hooks": "^4.6.2",
    "eslint-plugin-react-refresh": "^0.4.12",
    "jsdom": "^25.0.0",
    "prettier": "^3.3.3",
    "typescript": "^5.6.2",
    "vite": "^5.4.6",
    "vitest": "^2.1.1"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

- [ ] **Step 3: Create tsconfig.node.json**

```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 4: Create vite.config.ts**

```typescript
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
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
```

- [ ] **Step 5: Create vitest.setup.ts**

```typescript
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 6: Create index.html**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>OSIRIS Console</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create .eslintrc.cjs**

```javascript
module.exports = {
  root: true,
  env: { browser: true, es2020: true, node: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
  ],
  ignorePatterns: ["dist", ".eslintrc.cjs"],
  parser: "@typescript-eslint/parser",
  plugins: ["react-refresh"],
  rules: {
    "react-refresh/only-export-components": [
      "warn",
      { allowConstantExport: true },
    ],
  },
};
```

- [ ] **Step 8: Create .prettierrc.json**

```json
{
  "semi": true,
  "singleQuote": false,
  "trailingComma": "es5",
  "printWidth": 100
}
```

- [ ] **Step 9: Create .gitignore**

```
node_modules
dist
*.local
```

- [ ] **Step 10: Create src/index.css**

```css
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --bg-alt: #161b22;
  --fg: #c9d1d9;
  --border: #30363d;
  --accent: #58a6ff;
  --danger: #f85149;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family:
    "SFMono-Regular",
    Consolas,
    "Liberation Mono",
    Menlo,
    monospace;
}
```

- [ ] **Step 11: Write the failing test**

Create `console/src/App.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("renders the console title", () => {
    render(<App />);
    expect(screen.getByText("OSIRIS Console")).toBeInTheDocument();
  });
});
```

- [ ] **Step 12: Install dependencies**

Run: `cd console && npm install`
Expected: installs successfully (no `App.tsx`/`main.tsx` yet, so nothing runs).

- [ ] **Step 13: Run the test to verify it fails**

Run: `cd console && npm test`
Expected: FAIL — `./App` module doesn't exist yet.

- [ ] **Step 14: Create the minimal App.tsx**

```tsx
export function App() {
  return <h1>OSIRIS Console</h1>;
}
```

- [ ] **Step 15: Create src/main.tsx**

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("root element not found");
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 16: Run the test to verify it passes**

Run: `cd console && npm test`
Expected: PASS (1 test).

- [ ] **Step 17: Verify build and lint**

Run: `cd console && npm run build`
Expected: succeeds, produces `console/dist/`.

Run: `cd console && npm run lint`
Expected: no errors.

- [ ] **Step 18: Commit**

```bash
git add console/
git commit -m "feat(console): scaffold Vite+React+TypeScript project with Vitest/ESLint/Prettier"
```

---

### Task 4: Zustand cross-cutting UI store

**Files:**
- Create: `console/src/store/uiStore.ts`
- Test: `console/src/store/uiStore.test.ts`

**Interfaces:**
- Produces: `useUiStore` (a Zustand hook) exposing `selectedEntity: string | null`, `timeRange: { since: number | null; until: number | null }`, `activeFilters: Record<string, string>`, and actions `selectEntity`, `setTimeRange`, `setFilter`, `clearFilter`. Not consumed by any screen in this phase — 7b-2's Process Explorer/Timeline and 7b-4's Entity Graph are the first real consumers.

- [ ] **Step 1: Write the failing test**

Create `console/src/store/uiStore.test.ts`:

```typescript
import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "./uiStore";

const initialState = useUiStore.getState();

beforeEach(() => {
  useUiStore.setState(initialState, true);
});

describe("useUiStore", () => {
  it("starts with no selection, no time range, and no filters", () => {
    const state = useUiStore.getState();
    expect(state.selectedEntity).toBeNull();
    expect(state.timeRange).toEqual({ since: null, until: null });
    expect(state.activeFilters).toEqual({});
  });

  it("selectEntity sets and clears the selected entity", () => {
    useUiStore.getState().selectEntity("process:abc123");
    expect(useUiStore.getState().selectedEntity).toBe("process:abc123");

    useUiStore.getState().selectEntity(null);
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("setTimeRange replaces the active time range", () => {
    useUiStore.getState().setTimeRange({ since: 1000, until: 2000 });
    expect(useUiStore.getState().timeRange).toEqual({ since: 1000, until: 2000 });
  });

  it("setFilter adds a filter without disturbing existing ones", () => {
    useUiStore.getState().setFilter("host", "web-01");
    useUiStore.getState().setFilter("severity", "high");
    expect(useUiStore.getState().activeFilters).toEqual({
      host: "web-01",
      severity: "high",
    });
  });

  it("clearFilter removes only the named filter", () => {
    useUiStore.getState().setFilter("host", "web-01");
    useUiStore.getState().setFilter("severity", "high");
    useUiStore.getState().clearFilter("host");
    expect(useUiStore.getState().activeFilters).toEqual({ severity: "high" });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- uiStore`
Expected: FAIL — `./uiStore` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/store/uiStore.ts`:

```typescript
import { create } from "zustand";

export interface TimeRange {
  since: number | null;
  until: number | null;
}

export interface UiState {
  selectedEntity: string | null;
  timeRange: TimeRange;
  activeFilters: Record<string, string>;
  selectEntity: (entityId: string | null) => void;
  setTimeRange: (range: TimeRange) => void;
  setFilter: (key: string, value: string) => void;
  clearFilter: (key: string) => void;
}

export const useUiStore = create<UiState>((set) => ({
  selectedEntity: null,
  timeRange: { since: null, until: null },
  activeFilters: {},
  selectEntity: (entityId) => set({ selectedEntity: entityId }),
  setTimeRange: (range) => set({ timeRange: range }),
  setFilter: (key, value) =>
    set((state) => ({ activeFilters: { ...state.activeFilters, [key]: value } })),
  clearFilter: (key) =>
    set((state) => {
      const next = { ...state.activeFilters };
      delete next[key];
      return { activeFilters: next };
    }),
}));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- uiStore`
Expected: PASS (5 tests).

- [ ] **Step 5: Run lint**

Run: `cd console && npm run lint`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add console/src/store/
git commit -m "feat(console): add Zustand store for cross-cutting UI state"
```

---

### Task 5: API client and TanStack Query hooks

**Files:**
- Create: `console/src/api/types.ts`
- Create: `console/src/api/client.ts`
- Create: `console/src/api/hooks.ts`
- Test: `console/src/api/client.test.ts`
- Test: `console/src/api/hooks.test.tsx`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: types `ApiHealth`, `CanonicalEvent`, `HealthState`, `SensorHealthEventData` from `./types`; functions `fetchHealth`, `fetchEvents`, `fetchAlerts`, `fetchIncidents`, class `ApiError` from `./client`; hooks `useHealth()`, `useEvents(eventType?: string)`, `useAlerts()`, `useIncidents()` from `./hooks`, each returning a TanStack Query `UseQueryResult`. Task 7 (Overview) consumes `useHealth`/`useAlerts`/`useIncidents`; Task 8 (Sensors) consumes `useEvents` and `CanonicalEvent`/`SensorHealthEventData`.

- [ ] **Step 1: Write types.ts (no test — plain type definitions)**

Create `console/src/api/types.ts`:

```typescript
export interface ApiHealth {
  healthy: boolean;
  event_count: number;
  last_write_at: number | null;
}

export type HealthState =
  | { state: "HEALTHY" }
  | { state: "DEGRADED"; last_error: string }
  | { state: "FAILED"; last_error: string };

export interface SensorHealthEventData {
  sensor_name: string;
  state: HealthState;
  events_processed: number;
  last_event_at: number | null;
}

export interface CanonicalEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  host: {
    host_id: string;
    hostname: string;
  };
  event_data: unknown;
}
```

- [ ] **Step 2: Write the failing test for client.ts**

Create `console/src/api/client.test.ts`:

```typescript
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("fetchHealth calls /api/v1/health and parses the response", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ healthy: true, event_count: 42, last_write_at: 1000 }), {
        status: 200,
      })
    );

    const health = await fetchHealth();

    expect(fetch).toHaveBeenCalledWith("/api/v1/health");
    expect(health).toEqual({ healthy: true, event_count: 42, last_write_at: 1000 });
  });

  it("fetchEvents with no eventType calls /api/v1/events with no query string", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents();

    expect(fetch).toHaveBeenCalledWith("/api/v1/events");
  });

  it("fetchEvents with an eventType adds the event_type query param", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchEvents({ eventType: "SENSOR_HEALTH" });

    expect(fetch).toHaveBeenCalledWith("/api/v1/events?event_type=SENSOR_HEALTH");
  });

  it("fetchAlerts calls /api/v1/alerts", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchAlerts();

    expect(fetch).toHaveBeenCalledWith("/api/v1/alerts");
  });

  it("fetchIncidents calls /api/v1/incidents", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));

    await fetchIncidents();

    expect(fetch).toHaveBeenCalledWith("/api/v1/incidents");
  });

  it("throws ApiError when the response is not ok", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));

    await expect(fetchHealth()).rejects.toThrow(ApiError);
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd console && npm test -- client.test`
Expected: FAIL — `./client` module doesn't exist yet.

- [ ] **Step 4: Write the implementation**

Create `console/src/api/client.ts`:

```typescript
import type { ApiHealth, CanonicalEvent } from "./types";

const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new ApiError(response.status, `GET ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

export function fetchHealth(): Promise<ApiHealth> {
  return apiGet<ApiHealth>("/health");
}

export function fetchEvents(params: { eventType?: string } = {}): Promise<CanonicalEvent[]> {
  const search = new URLSearchParams();
  if (params.eventType) {
    search.set("event_type", params.eventType);
  }
  const queryString = search.toString();
  return apiGet<CanonicalEvent[]>(`/events${queryString ? `?${queryString}` : ""}`);
}

export function fetchAlerts(): Promise<unknown[]> {
  return apiGet<unknown[]>("/alerts");
}

export function fetchIncidents(): Promise<unknown[]> {
  return apiGet<unknown[]>("/incidents");
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd console && npm test -- client.test`
Expected: PASS (6 tests).

- [ ] **Step 6: Write the failing test for hooks.ts**

Create `console/src/api/hooks.test.tsx`:

```tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import * as client from "./client";
import { useAlerts, useEvents, useHealth, useIncidents } from "./hooks";

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

describe("api hooks", () => {
  it("useHealth resolves with fetchHealth's result", async () => {
    vi.spyOn(client, "fetchHealth").mockResolvedValue({
      healthy: true,
      event_count: 3,
      last_write_at: 500,
    });

    const { result } = renderHook(() => useHealth(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual({ healthy: true, event_count: 3, last_write_at: 500 });
  });

  it("useEvents forwards the eventType to fetchEvents", async () => {
    const spy = vi.spyOn(client, "fetchEvents").mockResolvedValue([]);

    const { result } = renderHook(() => useEvents("SENSOR_HEALTH"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ eventType: "SENSOR_HEALTH" });
  });

  it("useAlerts resolves with fetchAlerts's result", async () => {
    vi.spyOn(client, "fetchAlerts").mockResolvedValue([{ id: "a1" }]);

    const { result } = renderHook(() => useAlerts(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "a1" }]);
  });

  it("useIncidents resolves with fetchIncidents's result", async () => {
    vi.spyOn(client, "fetchIncidents").mockResolvedValue([{ id: "i1" }]);

    const { result } = renderHook(() => useIncidents(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([{ id: "i1" }]);
  });
});
```

- [ ] **Step 7: Run the test to verify it fails**

Run: `cd console && npm test -- hooks.test`
Expected: FAIL — `./hooks` module doesn't exist yet.

- [ ] **Step 8: Write the implementation**

Create `console/src/api/hooks.ts`:

```typescript
import { useQuery } from "@tanstack/react-query";
import { fetchAlerts, fetchEvents, fetchHealth, fetchIncidents } from "./client";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
}

export function useEvents(eventType?: string) {
  return useQuery({
    queryKey: ["events", eventType ?? "all"],
    queryFn: () => fetchEvents({ eventType }),
  });
}

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: fetchAlerts,
  });
}

export function useIncidents() {
  return useQuery({
    queryKey: ["incidents"],
    queryFn: fetchIncidents,
  });
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cd console && npm test -- hooks.test`
Expected: PASS (4 tests).

- [ ] **Step 10: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add console/src/api/
git commit -m "feat(console): add typed API client and TanStack Query hooks"
```

---

### Task 6: App shell — layout, nav, routing, error boundary

**Files:**
- Create: `console/src/app/navItems.ts`
- Create: `console/src/app/ErrorBoundary.tsx`
- Create: `console/src/app/Shell.tsx`
- Create: `console/src/screens/ComingSoon.tsx`
- Modify: `console/src/App.tsx`
- Test: `console/src/app/ErrorBoundary.test.tsx`
- Test: `console/src/App.test.tsx` (rewritten)

**Interfaces:**
- Consumes: nothing from earlier tasks (Tasks 7-8 will import `NAV_ITEMS` from `./navItems` to flip individual items to `enabled: true`, and will edit `App.tsx`'s route list).
- Produces: `NAV_ITEMS: NavItem[]` (`{ label: string; path: string; enabled: boolean }`) from `./navItems`; `ErrorBoundary` component from `./ErrorBoundary`; `Shell` component from `./Shell`; `ComingSoon({ label }: { label: string })` from `../screens/ComingSoon`; `App` (rewritten) rendering the full route table with all 13 screens, all pointing at `ComingSoon` initially.

- [ ] **Step 1: Create navItems.ts (no test — plain data)**

Create `console/src/app/navItems.ts`:

```typescript
export interface NavItem {
  label: string;
  path: string;
  enabled: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Overview", path: "/", enabled: false },
  { label: "Live Events", path: "/live-events", enabled: false },
  { label: "Process Explorer", path: "/processes", enabled: false },
  { label: "Filesystem", path: "/files", enabled: false },
  { label: "Network", path: "/network", enabled: false },
  { label: "Containers", path: "/containers", enabled: false },
  { label: "Timeline", path: "/timeline", enabled: false },
  { label: "Alerts", path: "/alerts", enabled: false },
  { label: "Incidents", path: "/incidents", enabled: false },
  { label: "Threat Hunting", path: "/hunting", enabled: false },
  { label: "Entity Graph", path: "/graph", enabled: false },
  { label: "Evidence", path: "/evidence", enabled: false },
  { label: "Sensors", path: "/sensors", enabled: false },
];
```

- [ ] **Step 2: Create ComingSoon.tsx (no test — trivial, covered via App.test.tsx below)**

Create `console/src/screens/ComingSoon.tsx`:

```tsx
export interface ComingSoonProps {
  label: string;
}

export function ComingSoon({ label }: ComingSoonProps) {
  return (
    <div>
      <h1>{label}</h1>
      <p>This screen is not implemented yet.</p>
    </div>
  );
}
```

- [ ] **Step 3: Write the failing test for ErrorBoundary**

Create `console/src/app/ErrorBoundary.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

function Boom(): never {
  throw new Error("kaboom");
}

describe("ErrorBoundary", () => {
  it("renders children when there is no error", () => {
    render(
      <ErrorBoundary>
        <p>all good</p>
      </ErrorBoundary>
    );
    expect(screen.getByText("all good")).toBeInTheDocument();
  });

  it("renders a fallback when a child throws", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>
    );

    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText("kaboom")).toBeInTheDocument();

    vi.restoreAllMocks();
  });
});
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd console && npm test -- ErrorBoundary`
Expected: FAIL — `./ErrorBoundary` module doesn't exist yet.

- [ ] **Step 5: Write the implementation**

Create `console/src/app/ErrorBoundary.tsx`:

```tsx
import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Console screen crashed", error, info);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div role="alert">
          <h1>Something went wrong</h1>
          <p>{this.state.error.message}</p>
        </div>
      );
    }
    return this.props.children;
  }
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd console && npm test -- ErrorBoundary`
Expected: PASS (2 tests).

- [ ] **Step 7: Write Shell.tsx (covered by the App.test.tsx rewrite in Step 9)**

Create `console/src/app/Shell.tsx`:

```tsx
import { NavLink, Outlet } from "react-router-dom";
import { NAV_ITEMS } from "./navItems";

export function Shell() {
  return (
    <div>
      <nav aria-label="main">
        <div>OSIRIS</div>
        <ul>
          {NAV_ITEMS.map((item) =>
            item.enabled ? (
              <li key={item.path}>
                <NavLink to={item.path} end={item.path === "/"}>
                  {item.label}
                </NavLink>
              </li>
            ) : (
              <li key={item.path} aria-disabled="true">
                {item.label}
              </li>
            )
          )}
        </ul>
      </nav>
      <main>
        <Outlet />
      </main>
    </div>
  );
}
```

- [ ] **Step 8: Rewrite App.tsx to wire routing, the shell, and the error boundary**

Replace the entire content of `console/src/App.tsx`:

```tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ErrorBoundary>
          <Routes>
            <Route element={<Shell />}>
              <Route path="/" element={<ComingSoon label="Overview" />} />
              <Route path="/live-events" element={<ComingSoon label="Live Events" />} />
              <Route path="/processes" element={<ComingSoon label="Process Explorer" />} />
              <Route path="/files" element={<ComingSoon label="Filesystem" />} />
              <Route path="/network" element={<ComingSoon label="Network" />} />
              <Route path="/containers" element={<ComingSoon label="Containers" />} />
              <Route path="/timeline" element={<ComingSoon label="Timeline" />} />
              <Route path="/alerts" element={<ComingSoon label="Alerts" />} />
              <Route path="/incidents" element={<ComingSoon label="Incidents" />} />
              <Route path="/hunting" element={<ComingSoon label="Threat Hunting" />} />
              <Route path="/graph" element={<ComingSoon label="Entity Graph" />} />
              <Route path="/evidence" element={<ComingSoon label="Evidence" />} />
              <Route path="/sensors" element={<ComingSoon label="Sensors" />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
```

- [ ] **Step 9: Rewrite App.test.tsx for the new shell**

Replace the entire content of `console/src/App.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { NAV_ITEMS } from "./app/navItems";

describe("App", () => {
  it("renders every nav item's label", () => {
    render(<App />);
    for (const item of NAV_ITEMS) {
      expect(screen.getByText(item.label)).toBeInTheDocument();
    }
  });

  it("shows the Overview 'coming soon' placeholder at the root path", () => {
    render(<App />);
    expect(screen.getByText("This screen is not implemented yet.")).toBeInTheDocument();
  });

  it("renders no nav links yet, since no item is enabled", () => {
    render(<App />);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
});
```

- [ ] **Step 10: Run the tests to verify they pass**

Run: `cd console && npm test`
Expected: PASS (all tests across the project).

- [ ] **Step 11: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 12: Commit**

```bash
git add console/src/app/ console/src/screens/ComingSoon.tsx console/src/App.tsx console/src/App.test.tsx
git commit -m "feat(console): add app shell with routing, fixed nav, and an error boundary"
```

---

### Task 7: Overview screen

**Files:**
- Create: `console/src/screens/overview/Overview.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/overview/Overview.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useHealth`, `useAlerts`, `useIncidents` from `../../api/hooks` (Task 5).
- Produces: `Overview` component from `./Overview`, mounted at `/`.

- [ ] **Step 1: Write the failing test**

Create `console/src/screens/overview/Overview.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Overview } from "./Overview";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useHealth>;
}

describe("Overview", () => {
  it("shows loading state while health is loading", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(mockQueryResult({ isLoading: true }));
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ isLoading: true }));
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ isLoading: true }));

    render(<Overview />);

    expect(screen.getByText("Loading health…")).toBeInTheDocument();
  });

  it("shows storage health and counts once loaded", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(
      mockQueryResult({ data: { healthy: true, event_count: 1234, last_write_at: 999 } })
    );
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [1, 2, 3] }));
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [1] }));

    render(<Overview />);

    expect(screen.getByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("1234")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
  });

  it("shows an error when health fails to load", () => {
    vi.mocked(hooks.useHealth).mockReturnValue(
      mockQueryResult({ isError: true, error: new Error("network down") })
    );
    vi.mocked(hooks.useAlerts).mockReturnValue(mockQueryResult({ data: [] }));
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));

    render(<Overview />);

    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- Overview`
Expected: FAIL — `./Overview` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/overview/Overview.tsx`:

```tsx
import { useAlerts, useHealth, useIncidents } from "../../api/hooks";

export function Overview() {
  const health = useHealth();
  const alerts = useAlerts();
  const incidents = useIncidents();

  return (
    <div>
      <h1>Overview</h1>
      <section aria-label="storage health">
        {health.isLoading && <p>Loading health…</p>}
        {health.isError && (
          <p role="alert">Failed to load health: {(health.error as Error).message}</p>
        )}
        {health.data && (
          <dl>
            <dt>Storage</dt>
            <dd>{health.data.healthy ? "Healthy" : "Unhealthy"}</dd>
            <dt>Event count</dt>
            <dd>{health.data.event_count}</dd>
          </dl>
        )}
      </section>
      <section aria-label="counts">
        <div>
          <span>Alerts</span>
          <strong>{alerts.isLoading ? "…" : alerts.isError ? "error" : (alerts.data?.length ?? 0)}</strong>
        </div>
        <div>
          <span>Incidents</span>
          <strong>
            {incidents.isLoading ? "…" : incidents.isError ? "error" : (incidents.data?.length ?? 0)}
          </strong>
        </div>
      </section>
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- Overview`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire it into the route table**

In `console/src/App.tsx`, add the import:

```tsx
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";
```

becomes:

```tsx
import { ErrorBoundary } from "./app/ErrorBoundary";
import { Shell } from "./app/Shell";
import { ComingSoon } from "./screens/ComingSoon";
import { Overview } from "./screens/overview/Overview";
```

and change:

```tsx
              <Route path="/" element={<ComingSoon label="Overview" />} />
```

to:

```tsx
              <Route path="/" element={<Overview />} />
```

- [ ] **Step 6: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Overview", path: "/", enabled: false },
```

to:

```typescript
  { label: "Overview", path: "/", enabled: true },
```

- [ ] **Step 7: Update App.test.tsx for the now-enabled Overview link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("shows the Overview 'coming soon' placeholder at the root path", () => {
    render(<App />);
    expect(screen.getByText("This screen is not implemented yet.")).toBeInTheDocument();
  });

  it("renders no nav links yet, since no item is enabled", () => {
    render(<App />);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
```

with:

```tsx
  it("shows the Overview screen at the root path", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders exactly one nav link, for Overview", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveTextContent("Overview");
  });
```

- [ ] **Step 8: Run the full test suite**

Run: `cd console && npm test`
Expected: PASS (all tests). Note `Overview`'s own network calls run against the real `useHealth`/`useAlerts`/`useIncidents` hooks here (unmocked, hitting `fetch` inside `App.test.tsx`'s render) — since there's no server running in the test environment, `fetch` will reject; this is fine because the test only asserts the heading/link text, not loaded data, and `QueryClientProvider`'s default retry behavior won't hang the test (Vitest's default timeout is enough for a single failed fetch attempt). If this flakes in CI, that's a signal to give `App.test.tsx` its own `QueryClient` with `retry: false` the same way `hooks.test.tsx` does — note this as a follow-up rather than blocking this task on it.

- [ ] **Step 9: Verify build and lint**

Run: `cd console && npm run build && npm run lint`
Expected: both succeed.

- [ ] **Step 10: Commit**

```bash
git add console/src/screens/overview/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Overview screen"
```

---

### Task 8: Sensors screen

**Files:**
- Create: `console/src/screens/sensors/rollup.ts`
- Create: `console/src/screens/sensors/Sensors.tsx`
- Modify: `console/src/App.tsx`
- Modify: `console/src/app/navItems.ts`
- Test: `console/src/screens/sensors/rollup.test.ts`
- Test: `console/src/screens/sensors/Sensors.test.tsx`
- Test: `console/src/App.test.tsx` (extended)

**Interfaces:**
- Consumes: `useEvents` from `../../api/hooks` (Task 5); `CanonicalEvent`, `SensorHealthEventData`, `HealthState` from `../../api/types` (Task 5); the wire shape pinned by Task 1's backend test.
- Produces: `rollupSensorHealth(events: CanonicalEvent[]): SensorRollupRow[]` and `SensorRollupRow` from `./rollup`; `Sensors` component from `./Sensors`, mounted at `/sensors`.

- [ ] **Step 1: Write the failing test for the rollup function**

Create `console/src/screens/sensors/rollup.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import type { CanonicalEvent } from "../../api/types";
import { rollupSensorHealth } from "./rollup";

function sensorHealthEvent(overrides: {
  hostId?: string;
  timestamp?: number;
  sensorName?: string;
  state?: "HEALTHY" | "DEGRADED" | "FAILED";
  lastError?: string;
  lastEventAt?: number | null;
}): CanonicalEvent {
  const {
    hostId = "host-1",
    timestamp = 1000,
    sensorName = "network",
    state = "HEALTHY",
    lastError,
    lastEventAt = timestamp,
  } = overrides;

  return {
    event_id: `evt-${timestamp}-${sensorName}`,
    event_type: "SENSOR_HEALTH",
    timestamp,
    host: { host_id: hostId, hostname: "h" },
    event_data: {
      sensor_name: sensorName,
      state: state === "HEALTHY" ? { state } : { state, last_error: lastError ?? "boom" },
      events_processed: 1,
      last_event_at: lastEventAt,
    },
  };
}

describe("rollupSensorHealth", () => {
  it("ignores events that are not SENSOR_HEALTH", () => {
    const events: CanonicalEvent[] = [
      { ...sensorHealthEvent({}), event_type: "PROCESS_EXEC" },
    ];
    expect(rollupSensorHealth(events)).toEqual([]);
  });

  it("produces one row per (host, sensor)", () => {
    const events = [
      sensorHealthEvent({ hostId: "host-1", sensorName: "network" }),
      sensorHealthEvent({ hostId: "host-1", sensorName: "exec" }),
      sensorHealthEvent({ hostId: "host-2", sensorName: "network" }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toHaveLength(3);
  });

  it("keeps the most recent event per (host, sensor)", () => {
    const events = [
      sensorHealthEvent({ timestamp: 1000, lastEventAt: 1000, state: "HEALTHY" }),
      sensorHealthEvent({
        timestamp: 2000,
        lastEventAt: 2000,
        state: "FAILED",
        lastError: "eBPF load failure: verifier rejected program",
      }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toHaveLength(1);
    expect(rows[0].state).toBe("FAILED");
    expect(rows[0].lastError).toBe("eBPF load failure: verifier rejected program");
  });

  it("surfaces the sensor name, state, and last_error fields", () => {
    const events = [
      sensorHealthEvent({
        hostId: "host-1",
        sensorName: "network",
        state: "DEGRADED",
        lastError: "queue overflow: dropped 12 events",
        lastEventAt: 5000,
      }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows).toEqual([
      {
        hostId: "host-1",
        sensorName: "network",
        state: "DEGRADED",
        lastError: "queue overflow: dropped 12 events",
        lastEventAt: 5000,
      },
    ]);
  });

  it("ignores malformed event_data instead of throwing", () => {
    const malformed: CanonicalEvent = {
      event_id: "evt-bad",
      event_type: "SENSOR_HEALTH",
      timestamp: 1000,
      host: { host_id: "host-1", hostname: "h" },
      event_data: { unexpected: "shape" },
    };

    expect(rollupSensorHealth([malformed])).toEqual([]);
  });

  it("sorts rows by sensor name", () => {
    const events = [
      sensorHealthEvent({ sensorName: "network" }),
      sensorHealthEvent({ hostId: "host-2", sensorName: "exec" }),
    ];

    const rows = rollupSensorHealth(events);

    expect(rows.map((r) => r.sensorName)).toEqual(["exec", "network"]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd console && npm test -- rollup.test`
Expected: FAIL — `./rollup` module doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `console/src/screens/sensors/rollup.ts`:

```typescript
import type { CanonicalEvent } from "../../api/types";

export type SensorRollupState = "HEALTHY" | "DEGRADED" | "FAILED";

export interface SensorRollupRow {
  hostId: string;
  sensorName: string;
  state: SensorRollupState;
  lastError: string | null;
  lastEventAt: number | null;
}

const SEVERITY: Record<SensorRollupState, number> = {
  HEALTHY: 0,
  DEGRADED: 1,
  FAILED: 2,
};

interface SensorHealthEventDataShape {
  sensor_name: string;
  state: { state: SensorRollupState; last_error?: string };
  last_event_at: number | null;
}

function isSensorHealthEventData(value: unknown): value is SensorHealthEventDataShape {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.sensor_name !== "string") {
    return false;
  }
  if (typeof record.state !== "object" || record.state === null) {
    return false;
  }
  const state = (record.state as Record<string, unknown>).state;
  return state === "HEALTHY" || state === "DEGRADED" || state === "FAILED";
}

/**
 * Reduces SensorHealth events (ARCHITECTURE.md §23) to one row per
 * (host, sensor): the most recently reported event wins.
 */
export function rollupSensorHealth(events: CanonicalEvent[]): SensorRollupRow[] {
  const latest = new Map<string, SensorRollupRow>();

  for (const event of events) {
    if (event.event_type !== "SENSOR_HEALTH") {
      continue;
    }
    if (!isSensorHealthEventData(event.event_data)) {
      continue;
    }

    const data = event.event_data;
    const key = `${event.host.host_id}:${data.sensor_name}`;
    const candidateTime = data.last_event_at ?? event.timestamp;
    const candidate: SensorRollupRow = {
      hostId: event.host.host_id,
      sensorName: data.sensor_name,
      state: data.state.state,
      lastError: data.state.last_error ?? null,
      lastEventAt: data.last_event_at,
    };

    const existing = latest.get(key);
    if (!existing || candidateTime >= (existing.lastEventAt ?? 0)) {
      latest.set(key, candidate);
    }
  }

  return Array.from(latest.values()).sort((a, b) => a.sensorName.localeCompare(b.sensorName));
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd console && npm test -- rollup.test`
Expected: PASS (6 tests).

- [ ] **Step 5: Write the failing test for the Sensors screen**

Create `console/src/screens/sensors/Sensors.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { Sensors } from "./Sensors";

vi.mock("../../api/hooks");

function mockEventsResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useEvents>;
}

describe("Sensors", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockEventsResult({ isLoading: true }));
    render(<Sensors />);
    expect(screen.getByText("Loading sensor health…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockEventsResult({ isError: true, error: new Error("network down") })
    );
    render(<Sensors />);
    expect(screen.getByRole("alert")).toHaveTextContent("network down");
  });

  it("shows an empty state when there is no sensor health data", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(mockEventsResult({ data: [] }));
    render(<Sensors />);
    expect(screen.getByText("No sensor health data reported yet.")).toBeInTheDocument();
  });

  it("renders a row per sensor from the rollup", () => {
    vi.mocked(hooks.useEvents).mockReturnValue(
      mockEventsResult({
        data: [
          {
            event_id: "evt-1",
            event_type: "SENSOR_HEALTH",
            timestamp: 5000,
            host: { host_id: "host-1", hostname: "web-01" },
            event_data: {
              sensor_name: "network",
              state: { state: "FAILED", last_error: "eBPF load failure" },
              events_processed: 10,
              last_event_at: 5000,
            },
          },
        ],
      })
    );

    render(<Sensors />);

    expect(screen.getByText("network")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByText("eBPF load failure")).toBeInTheDocument();
  });
});
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd console && npm test -- Sensors.test`
Expected: FAIL — `./Sensors` module doesn't exist yet.

- [ ] **Step 7: Write the implementation**

Create `console/src/screens/sensors/Sensors.tsx`:

```tsx
import { useEvents } from "../../api/hooks";
import { rollupSensorHealth } from "./rollup";

export function Sensors() {
  const events = useEvents("SENSOR_HEALTH");
  const rows = events.data ? rollupSensorHealth(events.data) : [];

  return (
    <div>
      <h1>Sensors</h1>
      {events.isLoading && <p>Loading sensor health…</p>}
      {events.isError && (
        <p role="alert">Failed to load sensor health: {(events.error as Error).message}</p>
      )}
      {!events.isLoading && !events.isError && rows.length === 0 && (
        <p>No sensor health data reported yet.</p>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Sensor</th>
              <th>State</th>
              <th>Last error</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.hostId}:${row.sensorName}`}>
                <td>{row.hostId}</td>
                <td>{row.sensorName}</td>
                <td>{row.state}</td>
                <td>{row.lastError ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd console && npm test -- Sensors.test`
Expected: PASS (4 tests).

- [ ] **Step 9: Wire it into the route table**

In `console/src/App.tsx`, add the import:

```tsx
import { Overview } from "./screens/overview/Overview";
```

becomes:

```tsx
import { Overview } from "./screens/overview/Overview";
import { Sensors } from "./screens/sensors/Sensors";
```

and change:

```tsx
              <Route path="/sensors" element={<ComingSoon label="Sensors" />} />
```

to:

```tsx
              <Route path="/sensors" element={<Sensors />} />
```

- [ ] **Step 10: Enable the nav item**

In `console/src/app/navItems.ts`, change:

```typescript
  { label: "Sensors", path: "/sensors", enabled: false },
```

to:

```typescript
  { label: "Sensors", path: "/sensors", enabled: true },
```

- [ ] **Step 11: Update App.test.tsx for the now-enabled Sensors link**

In `console/src/App.test.tsx`, replace:

```tsx
  it("renders exactly one nav link, for Overview", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveTextContent("Overview");
  });
```

with:

```tsx
  it("renders exactly two nav links, for Overview and Sensors", () => {
    render(<App />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Sensors"]);
  });
```

- [ ] **Step 12: Run the full test suite, build, and lint**

Run: `cd console && npm test && npm run build && npm run lint`
Expected: all pass.

- [ ] **Step 13: Commit**

```bash
git add console/src/screens/sensors/ console/src/App.tsx console/src/app/navItems.ts console/src/App.test.tsx
git commit -m "feat(console): add the Sensors screen"
```

---

### Task 9: Manual end-to-end smoke verification

This task has no code changes — it confirms the whole stack (Task 1's
backend wire shape, Task 2's CORS layer, and Tasks 3-8's Console) works
together against a real `osiris-server`, since Tasks 1-8's automated
tests each verify one layer in isolation (backend via `cargo test`,
frontend via mocked `fetch`/hooks).

**Files:** none.

- [ ] **Step 1: Start osiris-server with dev_cors enabled**

Create a minimal server config with `dev_cors: true` added (reuse an
existing dev config or the minimal shape from `config.rs`'s tests), then
run:

```bash
cargo run --bin osiris-server -- path/to/that/config.yaml
```

Expected: server starts and binds to its `listen_addr` (e.g.
`127.0.0.1:8080`).

- [ ] **Step 2: Insert a synthetic SensorHealth event into that server's storage**

Stop the server. Add this temporary test to
`crates/osiris-api/src/lib.rs`'s `mod tests` block, pointed at the same
`db_path` the server config from Step 1 uses (so it writes into the same
database file the server will read from):

```rust
    #[test]
    fn temporary_seed_sensor_health_event_for_manual_smoke_test() {
        let storage = SqliteStorage::open("/path/to/the/same/db_path/from/step/1").unwrap();
        storage
            .write(&sensor_health_event(Uuid::new_v4(), "network", 5000))
            .unwrap();
    }
```

Run: `cargo test -p osiris-api temporary_seed_sensor_health_event_for_manual_smoke_test -- --ignored --nocapture`
(drop `--ignored` if you didn't mark it `#[ignore]`; the point is just to
execute this one test once).

Then delete the temporary test — it must not be committed. Restart the
server afterward so it re-reads the now-seeded database.

- [ ] **Step 3: Start the Console dev server**

```bash
cd console && npm run dev
```

Expected: Vite prints a local URL (typically `http://localhost:5173`).

- [ ] **Step 4: Verify in a browser**

Open the printed URL. Confirm:
- The Overview screen loads and shows a non-zero event count.
- Navigating to Sensors (now an enabled nav link) shows one row for the
  synthetic event, with the correct sensor name, `FAILED` state, and
  `last_error` text.
- No CORS errors appear in the browser console.

- [ ] **Step 5: Report the result**

No commit for this task — record in the PR/handoff notes (or directly to
the user) that the manual smoke check passed, including which config/db
path was used, since this is the only step in the plan that isn't
captured by an automated test.

---
