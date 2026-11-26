import { defineConfig, devices } from "@playwright/test";

// UI end-to-end tests: the built interface in Chromium with the scripted
// back end (VITE_LK_MOCK=1). The real Rust back end is covered by the Rust
// tests and by e2e-tauri (real application through WebDriver).
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.spec.ts",
  fullyParallel: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:5175",
    trace: "off",
    ...devices["Desktop Chrome"],
    viewport: { width: 1180, height: 760 },
  },
  webServer: {
    command: "npx vite --port 5175 --strictPort",
    env: { VITE_LK_MOCK: "1" },
    url: "http://127.0.0.1:5175",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
