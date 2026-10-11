import { test as base, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { STACK_FILE } from "./global-setup";

type Problems = { consoleErrors: string[]; failedRequests: string[] };

export const test = base.extend<{ problems: Problems; loggedIn: Page }>({
  problems: async ({ page }, use) => {
    const p: Problems = { consoleErrors: [], failedRequests: [] };
    page.on("console", (m) => m.type() === "error" && p.consoleErrors.push(m.text()));
    page.on("pageerror", (e) => p.consoleErrors.push(String(e)));
    page.on("requestfailed", (r) => p.failedRequests.push(`${r.method()} ${r.url()} ${r.failure()?.errorText}`));
    page.on("response", (r) => r.status() >= 400 && p.failedRequests.push(`${r.status()} ${r.url()}`));
    await use(p);
    expect(p.consoleErrors, "console errors").toEqual([]);
    expect(p.failedRequests, "failed requests").toEqual([]);
  },
  loggedIn: async ({ page, problems }, use) => {
    void problems;
    const { username, password } = JSON.parse(readFileSync(STACK_FILE, "utf8"));
    await page.goto("/login");
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Log in" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await use(page);
  },
});
export { expect };
