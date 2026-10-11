import { spawn } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const STACK_FILE = path.join(here, ".stack.json");
const PORT = 8080;

function portInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ port, host: "127.0.0.1" });
    s.once("connect", () => {
      s.destroy();
      resolve(true);
    });
    s.once("error", () => resolve(false));
  });
}

// Starts the seeded osiris-stack and returns the teardown. osiris-stack exits
// (dropping its child osiris-server) when its stdin reaches EOF, so teardown
// closes stdin and only falls back to a hard kill, which would orphan the
// server on Windows.
export default async function globalSetup() {
  rmSync(STACK_FILE, { force: true });
  if (await portInUse(PORT)) {
    throw new Error(
      `port ${PORT} is already in use; stop whatever listens there (a stale osiris-server?) before running e2e`,
    );
  }
  const repo = path.resolve(here, "../..");
  const exe = process.platform === "win32" ? "osiris-stack.exe" : "osiris-stack";
  const bin = path.join(process.env.OSIRIS_BIN_DIR ?? path.join(repo, "target", "release"), exe);
  if (!existsSync(bin)) {
    throw new Error(
      `${bin} missing: cargo build --release -p osiris-server -p osiris-real-linux-tests --bin osiris-stack`,
    );
  }
  const child = spawn(bin, ["--out", STACK_FILE, "--port", String(PORT)], {
    cwd: repo,
    stdio: ["pipe", "inherit", "inherit"],
  });
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));

  const teardown = async () => {
    if (child.exitCode !== null) return;
    child.stdin?.end();
    const timer = setTimeout(() => child.kill(), 30_000);
    await exited;
    clearTimeout(timer);
  };

  const deadline = Date.now() + 90_000;
  while (!existsSync(STACK_FILE)) {
    if (child.exitCode !== null) throw new Error(`osiris-stack exited (${child.exitCode})`);
    if (Date.now() > deadline) {
      await teardown();
      throw new Error("osiris-stack not ready in 90s");
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return teardown;
}
