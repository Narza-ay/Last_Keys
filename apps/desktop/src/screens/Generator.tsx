// Password and passphrase generator (generation runs in Rust with the OS
// random number generator).

import { useEffect, useState } from "react";
import type { GeneratedView, PassphraseOptions, PasswordOptions } from "../api/types";
import { Button, Segmented, Select, StrengthMeter, Toggle } from "../components/controls";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";

function Colored({ value }: { value: string }) {
  return (
    <>
      {Array.from(value).map((ch, i) => (
        <span key={i} className={/\d/.test(ch) ? "digit" : /[\p{L}\s-]/u.test(ch) ? undefined : "symbol"}>
          {ch}
        </span>
      ))}
    </>
  );
}

export function Generator() {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [password, setPassword] = useState<PasswordOptions>({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  });
  const [phrase, setPhrase] = useState<PassphraseOptions>({
    words: 5,
    separator: "-",
    capitalize: true,
    includeNumber: false,
  });
  const [result, setResult] = useState<GeneratedView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  // A new secret whenever an option changes or "regenerate" is pressed.
  useEffect(() => {
    let cancelled = false;
    const request = mode === "password" ? backend.generatePassword(password) : backend.generatePassphrase(phrase);
    request
      .then((r) => {
        if (cancelled) return;
        setResult(r);
        setError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setResult(null);
        setError(errorText(err));
      });
    return () => {
      cancelled = true;
    };
  }, [backend, mode, password, phrase, errorText, nonce]);

  const copy = async () => {
    if (!result) return;
    try {
      const r = await backend.copyText(result.value);
      toast(t("toast.copied", { seconds: r.clearsInSeconds }));
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-header">
          <h1>{t("generator.title")}</h1>
          <p>{t("generator.subtitle")}</p>
        </header>
        <div className="card">
          <div className="generated" data-testid="generated" aria-live="polite">
            {result ? <Colored value={result.value} /> : <span className="muted">{error ?? "…"}</span>}
          </div>
          <div className="card-section">
            {result ? <StrengthMeter level={result.level} bits={result.entropyBits} /> : null}
          </div>
          <div className="card-section generator-actions">
            <Button icon="sync" onClick={() => setNonce((n) => n + 1)}>
              {t("generator.regenerate")}
            </Button>
            <Button variant="primary" icon="copy" onClick={() => void copy()} disabled={!result}>
              {t("action.copy")}
            </Button>
          </div>
        </div>
        <div className="card">
          <div className="card-section">
            <Segmented
              label={t("generator.mode")}
              value={mode}
              onChange={setMode}
              options={[
                { value: "password", label: t("generator.password"), icon: "key" },
                { value: "passphrase", label: t("generator.passphrase"), icon: "note" },
              ]}
            />
          </div>
          {mode === "password" ? (
            <>
              <div className="card-section slider-row">
                <label htmlFor="gen-length">{t("generator.length")}</label>
                <output htmlFor="gen-length">{password.length}</output>
                <input
                  id="gen-length"
                  type="range"
                  min={8}
                  max={64}
                  value={password.length}
                  onChange={(e) => setPassword({ ...password, length: Number(e.target.value) })}
                />
              </div>
              <div className="card-section grid-2">
                <Toggle label={t("generator.lowercase")} checked={password.lowercase} onChange={(lowercase) => setPassword({ ...password, lowercase })} />
                <Toggle label={t("generator.uppercase")} checked={password.uppercase} onChange={(uppercase) => setPassword({ ...password, uppercase })} />
                <Toggle label={t("generator.digits")} checked={password.digits} onChange={(digits) => setPassword({ ...password, digits })} />
                <Toggle label={t("generator.symbols")} checked={password.symbols} onChange={(symbols) => setPassword({ ...password, symbols })} />
                <Toggle
                  label={t("generator.excludeAmbiguous")}
                  checked={password.excludeAmbiguous}
                  onChange={(excludeAmbiguous) => setPassword({ ...password, excludeAmbiguous })}
                />
              </div>
            </>
          ) : (
            <>
              <div className="card-section slider-row">
                <label htmlFor="gen-words">{t("generator.words")}</label>
                <output htmlFor="gen-words">{phrase.words}</output>
                <input
                  id="gen-words"
                  type="range"
                  min={3}
                  max={12}
                  value={phrase.words}
                  onChange={(e) => setPhrase({ ...phrase, words: Number(e.target.value) })}
                />
              </div>
              <div className="card-section grid-2">
                <Select
                  label={t("generator.separator")}
                  value={phrase.separator}
                  onChange={(e) => setPhrase({ ...phrase, separator: e.target.value })}
                  options={[
                    { value: "-", label: t("generator.separatorHyphen") },
                    { value: " ", label: t("generator.separatorSpace") },
                    { value: ".", label: t("generator.separatorDot") },
                    { value: "_", label: t("generator.separatorUnderscore") },
                  ]}
                />
                <div className="form" style={{ justifyContent: "flex-end" }}>
                  <Toggle label={t("generator.capitalize")} checked={phrase.capitalize} onChange={(capitalize) => setPhrase({ ...phrase, capitalize })} />
                  <Toggle label={t("generator.includeNumber")} checked={phrase.includeNumber} onChange={(includeNumber) => setPhrase({ ...phrase, includeNumber })} />
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
