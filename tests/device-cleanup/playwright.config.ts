import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "cleanup-devices.ts",
  timeout: 120_000,
  retries: 1,
  use: {
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  outputDir: "test-results",
});
