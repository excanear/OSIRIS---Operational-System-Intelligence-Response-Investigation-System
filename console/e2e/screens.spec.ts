import { test, expect } from "./fixtures";

// `seeded` is text that must appear because the seed produces it; null means an
// empty state is legitimate for that screen.
const SCREENS: { path: string; heading: RegExp; seeded: RegExp | null }[] = [
  { path: "/", heading: /^Overview$/, seeded: null },
  { path: "/live-events", heading: /^Live Events$/, seeded: null },
  { path: "/processes", heading: /^Process Explorer$/, seeded: /bash|curl|sshd/ },
  { path: "/files", heading: /^Filesystem$/, seeded: /\/var\/www\// },
  { path: "/network", heading: /^Network$/, seeded: /\d+\.\d+\.\d+\.\d+/ },
  { path: "/containers", heading: /^Containers$/, seeded: /[0-9a-f]{12}/ },
  { path: "/hosts", heading: /^Hosts$/, seeded: null },
  { path: "/groups", heading: /^Groups$/, seeded: null },
  { path: "/timeline", heading: /^Timeline$/, seeded: null },
  { path: "/alerts", heading: /^Alerts$/, seeded: /shell_wrote_file_to_web_root|HIGH/ },
  { path: "/incidents", heading: /^Incidents$/, seeded: null },
  { path: "/hunting", heading: /^Threat Hunting$/, seeded: null },
  { path: "/graph", heading: /^Entity Graph$/, seeded: null },
  { path: "/evidence", heading: /^Evidence$/, seeded: null },
  { path: "/sensors", heading: /^Sensors$/, seeded: null },
];

for (const s of SCREENS) {
  test(`${s.path} renders without errors`, async ({ loggedIn: page }, info) => {
    await page.goto(s.path);
    await expect(page.getByRole("heading", { level: 1, name: s.heading })).toBeVisible();
    if (s.seeded) await expect(page.getByText(s.seeded).first()).toBeVisible({ timeout: 15_000 });
    await page.waitForLoadState("networkidle");
    await info.attach("screen", { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
  });
}

test("process detail opens from the list", async ({ loggedIn: page }) => {
  await page.goto("/processes");
  await page.getByRole("link").filter({ hasText: /bash|curl|sshd/ }).first().click();
  await expect(page).toHaveURL(/\/processes\/.+/);
  await page.waitForLoadState("networkidle");
});

test("a group can be created and its policy editor opens", async ({ loggedIn: page }) => {
  await page.goto("/groups");
  await page.getByRole("button", { name: "New group" }).click();
  await page.getByLabel("Name").fill(`e2e-${Date.now()}`);
  await page.getByRole("button", { name: "Create" }).click();
  await page.getByRole("link", { name: /e2e-/ }).first().click();
  await expect(page.getByRole("heading", { name: /policy/i })).toBeVisible();
});
