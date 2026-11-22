import { defineConfig } from "@playwright/test";

// Runs against the local stack: ./scripts/demo-up.sh, then npm run e2e.
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  use: { baseURL: process.env.WARRANT_CONSOLE_URL ?? "http://localhost:3000", trace: "retain-on-failure" },
  reporter: [["list"], ["html", { open: "never" }]],
});
