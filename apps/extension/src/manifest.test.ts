// @vitest-environment node
// The manifests: least privilege, one ID per browser matching the native
// host's allowed list (crates/lk-bridge/src/native.rs).

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(__dirname, "..");
const read = (file: string) => JSON.parse(readFileSync(join(root, file), "utf8")) as Record<string, unknown>;
const base = read("manifest.base.json");
const chrome = { ...base, ...read("manifest.chrome.json") };
const firefox = { ...base, ...read("manifest.firefox.json") };
const native = readFileSync(join(root, "../../crates/lk-bridge/src/native.rs"), "utf8");

describe("manifests", () => {
  it("ask for the minimum", () => {
    for (const m of [chrome, firefox]) {
      expect(m.manifest_version).toBe(3);
      expect(m.permissions).toEqual(["activeTab", "nativeMessaging", "scripting", "storage"]);
      // Access to every site is optional, asked for in the popup (AUDIT P-9);
      // content scripts are registered only once it is granted.
      expect(m.optional_host_permissions).toEqual(["http://*/*", "https://*/*"]);
      expect(m).not.toHaveProperty("host_permissions");
      expect(m).not.toHaveProperty("content_scripts");
      expect(JSON.stringify(m)).not.toContain("<all_urls>");
      expect(m).not.toHaveProperty("web_accessible_resources");
      expect(m).not.toHaveProperty("externally_connectable");
      expect((m.content_security_policy as { extension_pages: string }).extension_pages).toBe(
        "script-src 'self'; object-src 'none'; base-uri 'none'",
      );
    }
    expect(chrome.background).toEqual({ service_worker: "background.js" });
    expect(firefox.background).toEqual({ scripts: ["background.js"] });
  });

  it("use the extension IDs the native host allows", () => {
    const der = Buffer.from(String(chrome.key), "base64");
    const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
    const id = Array.from(hex, (c) => String.fromCharCode(97 + Number.parseInt(c, 16))).join("");
    expect(native).toContain(`CHROMIUM_EXTENSION_IDS: &[&str] = &["${id}"]`);
    const gecko = (firefox.browser_specific_settings as { gecko: { id: string } }).gecko.id;
    expect(native).toContain(`FIREFOX_EXTENSION_IDS: &[&str] = &["${gecko}"]`);
  });

  it("are translated", () => {
    for (const lang of ["en", "fr"]) {
      const messages = JSON.parse(readFileSync(join(root, "public/_locales", lang, "messages.json"), "utf8"));
      expect(Object.keys(messages).sort()).toEqual(["actionTitle", "commandOpen", "extDescription", "extName"]);
    }
  });
});
