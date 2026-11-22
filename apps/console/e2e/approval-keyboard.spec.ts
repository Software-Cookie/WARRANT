import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { execFileSync, spawn } from "node:child_process";
import path from "node:path";
import { signIn } from "./helpers";

// Forward slashes: Git Bash on Windows treats backslashes literally.
const ROOT = path.resolve(__dirname, "../../..").split(path.sep).join("/");

// Parks a real escalation by running the gate-on demo with the decision left to the console, then completes the
// approval using only the keyboard.
test("an approver can complete a partial approval with the keyboard alone", async ({ page }) => {
  test.setTimeout(240_000);
  execFileSync("bash", [`${ROOT}/scripts/demo-reset.sh`], { stdio: "inherit" });
  await signIn(page, "r.menon@acme.example");
  const pendingIds = async () =>
    ((await (await page.request.get("/api/cp/escalations?state=pending")).json()) as { id: string }[]).map((e) => e.id);
  const before = new Set(await pendingIds());

  const run = spawn("bash", [`${ROOT}/scripts/demo-run.sh`, "--gate", "on", "--approve", "console"], { stdio: "inherit" });
  const exited = new Promise<number | null>((resolve) => run.on("exit", resolve));
  try {
    let id = "";
    await expect.poll(async () => {
      id = (await pendingIds()).find((candidate) => !before.has(candidate)) ?? "";
      return id;
    }, { timeout: 90_000, intervals: [1_000] }).toMatch(/^esc_/);

    await page.goto(`/approve/${id}`);
    await expect(page.getByRole("heading", { level: 1 })).toContainText("1,284");
    const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
    expect(axe.violations).toEqual([]);

    const partial = page.getByRole("button", { name: /Archive 1,072 safe/ });
    for (let i = 0; i < 60 && !(await partial.evaluate((el) => el === document.activeElement)); i++) {
      await page.keyboard.press("Tab");
    }
    await expect(partial).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: /Confirm archive 1,072 safe/i })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: "Decision recorded" })).toContainText("partial");

    expect(await exited).toBe(0);
  } finally {
    run.kill();
  }
});
