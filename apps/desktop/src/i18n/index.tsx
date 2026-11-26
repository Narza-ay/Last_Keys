// Translations. English is the reference catalogue: its keys type every
// call to t(), and the French catalogue must define exactly the same keys
// (checked by the compiler and by i18n.test.ts, including placeholders).

import { createContext, useContext, useMemo, type ReactNode } from "react";
import type { Language } from "../api/types";
import { en } from "./en";
import { fr } from "./fr";

export type MessageKey = keyof typeof en;
export type Catalogue = Record<MessageKey, string>;
export type Locale = "fr" | "en";

export const catalogues: Record<Locale, Catalogue> = { en, fr };

type PluralBase = {
  [K in MessageKey]: K extends `${infer B}.one` ? B : never;
}[MessageKey];

export type Vars = Record<string, string | number>;

/** The locale for a language setting ("system" follows the OS). */
export function resolveLocale(language: Language, systemLanguage: string): Locale {
  if (language === "fr" || language === "en") return language;
  return systemLanguage.toLowerCase().startsWith("fr") ? "fr" : "en";
}

export function translate(locale: Locale, key: MessageKey, vars?: Vars): string {
  const template = catalogues[locale][key];
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in vars ? String(vars[name]) : match,
  );
}

export interface I18n {
  locale: Locale;
  t: (key: MessageKey, vars?: Vars) => string;
  /** Plural form: uses `base.one` / `base.other`, with {count} available. */
  tn: (base: PluralBase, count: number, vars?: Vars) => string;
  date: (unixSeconds: number) => string;
  dateTime: (unixSeconds: number) => string;
  time: (unixSeconds: number) => string;
}

export function makeI18n(locale: Locale): I18n {
  const plural = new Intl.PluralRules(locale);
  const dateFormat = new Intl.DateTimeFormat(locale, { dateStyle: "medium" });
  const dateTimeFormat = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const timeFormat = new Intl.DateTimeFormat(locale, { timeStyle: "short" });
  return {
    locale,
    t: (key, vars) => translate(locale, key, vars),
    tn: (base, count, vars) => {
      const form = plural.select(count) === "one" ? "one" : "other";
      return translate(locale, `${base}.${form}` as MessageKey, { count, ...vars });
    },
    date: (s) => dateFormat.format(new Date(s * 1000)),
    dateTime: (s) => dateTimeFormat.format(new Date(s * 1000)),
    time: (s) => timeFormat.format(new Date(s * 1000)),
  };
}

const I18nContext = createContext<I18n>(makeI18n("en"));

export function I18nProvider({ locale, children }: { locale: Locale; children: ReactNode }) {
  const value = useMemo(() => makeI18n(locale), [locale]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  return useContext(I18nContext);
}
