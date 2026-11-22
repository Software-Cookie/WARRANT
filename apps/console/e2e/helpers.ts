import { expect, type Page } from "@playwright/test";

export async function signIn(page: Page, email: string) {
  await page.goto("/login");
  const code = process.env.WARRANT_DEMO_ACCESS_CODE;
  if (code) await page.getByLabel("Access code").fill(code);
  await page.locator(`input[type="radio"][value="${email}"]`).check();
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login/);
}
