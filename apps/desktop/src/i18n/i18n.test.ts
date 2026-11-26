import { catalogues, makeI18n, resolveLocale, translate, type MessageKey } from ".";
import { en } from "./en";
import { fr } from "./fr";

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe("catalogues", () => {
  it("define exactly the same keys in French and English", () => {
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort());
  });

  it("use the same placeholders in both languages", () => {
    for (const key of Object.keys(en) as MessageKey[]) {
      expect(placeholders(fr[key]), key).toEqual(placeholders(en[key]));
    }
  });

  it("have no empty translation", () => {
    for (const locale of ["en", "fr"] as const) {
      for (const [key, value] of Object.entries(catalogues[locale])) {
        expect(value.trim(), `${locale}:${key}`).not.toBe("");
      }
    }
  });

  it("define both plural forms together", () => {
    const keys = Object.keys(en);
    for (const key of keys.filter((k) => k.endsWith(".one"))) {
      expect(keys, key).toContain(key.replace(/\.one$/, ".other"));
    }
  });

  it("apply French typography (no-break spaces)", () => {
    expect(fr["unlock.useRecovery"]).toBe("Mot de passe maître oublié ?");
    expect(fr["devices.revokeTitle"]).toContain("« {name} »");
    for (const value of Object.values(fr)) expect(value).not.toMatch(/ [:;!?»]/);
  });

  it("translate every back-end error code", () => {
    const codes = [
      "no_vault", "vault_exists", "invalid_credentials", "weak_master_password", "password_mismatch",
      "not_found", "ambiguous", "invalid_input", "not_registered", "already_registered",
      "needs_master_password", "no_vault_on_server", "untrusted_device_list", "cannot_revoke_self",
      "no_totp", "wrong_item_type", "server_rollback", "device_revoked", "network",
      "invalid_server_url", "email_taken", "registration_closed", "rate_limited", "server",
      "corrupted", "internal", "locked", "invalid_setting", "clipboard", "invalid_recovery_key",
    ];
    for (const code of codes) expect(Object.keys(en)).toContain(`error.${code}`);
  });
});

describe("helpers", () => {
  it("resolve the system language", () => {
    expect(resolveLocale("system", "fr-CA")).toBe("fr");
    expect(resolveLocale("system", "de-DE")).toBe("en");
    expect(resolveLocale("en", "fr-FR")).toBe("en");
  });

  it("interpolate and pluralize", () => {
    expect(translate("en", "toast.copied", { seconds: 30 })).toBe(
      "Copied. The clipboard will be cleared in 30 s.",
    );
    const frI18n = makeI18n("fr");
    expect(frI18n.tn("settings.minutes", 1)).toBe("1 minute");
    expect(frI18n.tn("settings.minutes", 5)).toBe("5 minutes");
    expect(frI18n.tn("settings.seconds", 0)).toBe("0 seconde");
    expect(makeI18n("en").tn("settings.seconds", 0)).toBe("0 seconds");
  });
});
