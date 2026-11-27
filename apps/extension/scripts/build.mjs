// Builds the extension for Chromium browsers (Chrome, Brave) and Firefox:
// dist/chrome and dist/firefox, each a complete unpacked extension.
//
// The popup is a normal Vite page; the background and the content script
// are bundled as single classic scripts (no imports at run time: content
// scripts cannot be modules, and Firefox event pages are loaded the same
// way). Manifests: manifest.base.json merged with manifest.<browser>.json.

import { build } from "vite";
import react from "@vitejs/plugin-react";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const staging = join(root, "dist", "staging");
const common = { root, configFile: false, logLevel: "warn" };
const target = ["es2022", "chrome116", "firefox128"];

await rm(join(root, "dist"), { recursive: true, force: true });

await build({
  ...common,
  plugins: [react()],
  base: "./",
  build: {
    outDir: staging,
    emptyOutDir: true,
    target,
    sourcemap: false,
    rollupOptions: { input: join(root, "popup.html") },
  },
});

for (const [entry, file] of [
  ["src/background/index.ts", "background.js"],
  ["src/content/index.ts", "content.js"],
]) {
  await build({
    ...common,
    publicDir: false,
    define: { "process.env.NODE_ENV": JSON.stringify("production") },
    build: {
      outDir: staging,
      emptyOutDir: false,
      target,
      sourcemap: false,
      lib: { entry: join(root, entry), formats: ["iife"], name: "LastKeys", fileName: () => file },
    },
  });
}

// One logo for the desktop application and the extension.
await cp(join(root, "..", "desktop", "assets", "logo.svg"), join(staging, "logo.svg"));

const base = JSON.parse(await readFile(join(root, "manifest.base.json"), "utf8"));
const version = JSON.parse(await readFile(join(root, "package.json"), "utf8")).version;
for (const browser of ["chrome", "firefox"]) {
  const specific = JSON.parse(await readFile(join(root, `manifest.${browser}.json`), "utf8"));
  const out = join(root, "dist", browser);
  await mkdir(out, { recursive: true });
  await cp(staging, out, { recursive: true });
  const manifest = { ...base, ...specific, version };
  await writeFile(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}
// End-to-end tests only (never published): the same Chromium build with
// access to every site granted at installation, as after the user allowed
// it in the popup; the browser's permission prompt cannot be automated.
if (process.env.LK_EXTENSION_E2E === "1") {
  const out = join(root, "dist", "chrome-e2e");
  await cp(join(root, "dist", "chrome"), out, { recursive: true });
  const manifest = JSON.parse(await readFile(join(out, "manifest.json"), "utf8"));
  manifest.host_permissions = manifest.optional_host_permissions;
  delete manifest.optional_host_permissions;
  await writeFile(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}
await rm(staging, { recursive: true, force: true });
console.log("Built dist/chrome and dist/firefox");
