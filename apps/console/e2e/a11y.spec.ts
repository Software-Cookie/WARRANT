import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

const SURFACES = ["/", "/approvals", "/decisions", "/console", "/admin"];

test("public landing page has no accessibility violations", async ({ page }) => {
  await page.goto("/welcome");
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
  expect(results.violations).toEqual([]);
});

test("login has no accessibility violations", async ({ page }) => {
  await page.goto("/login");
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
  expect(results.violations).toEqual([]);
});

for (const surface of SURFACES) {
  test(`${surface} has no accessibility violations`, async ({ page }) => {
    await signIn(page, "priya@acme.example");
    await page.goto(surface);
    await page.waitForLoadState("networkidle");
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
    expect(results.violations).toEqual([]);
  });
}
