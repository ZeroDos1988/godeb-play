import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "on-first-retry",
  },
  webServer: {
    command: "npm run preview -- --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    // Viewports only; Chromium everywhere so CI does not need WebKit/Firefox.
    {
      name: "iphone",
      use: { ...devices["iPhone 13"], browserName: "chromium", isMobile: true, hasTouch: true },
    },
    {
      name: "pixel",
      use: { ...devices["Pixel 7"], browserName: "chromium", isMobile: true, hasTouch: true },
    },
  ],
});

