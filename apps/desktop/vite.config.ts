/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built files from disk; the dev server is only used by
// `tauri dev` and by the browser preview with the scripted back end
// (VITE_LK_MOCK=1), which never ships in a release build.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  build: {
    target: ["es2022", "safari16", "chrome110"],
    sourcemap: false,
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // The contrast test reads the colour tokens (CSS is empty otherwise).
    css: { include: [/tokens\.css/] },
  },
});
