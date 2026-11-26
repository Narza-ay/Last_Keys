// Unlock with the master password, or with the recovery key when it is
// forgotten (the master password is then reset in the settings).

import { useState, type FormEvent } from "react";
import { Button, Notice, PasswordField, TextField } from "../components/controls";
import { Logo } from "../components/Icon";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";

export function Unlock({ lockedByTimer = false }: { lockedByTimer?: boolean }) {
  const { t } = useI18n();
  const { backend, refreshStatus, errorText } = useApp();
  const [mode, setMode] = useState<"password" | "recovery">("password");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "password") await backend.unlock(secret);
      else await backend.unlockWithRecoveryKey(secret);
      setSecret("");
      await refreshStatus();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  const switchMode = () => {
    setMode((m) => (m === "password" ? "recovery" : "password"));
    setSecret("");
    setError(null);
  };

  return (
    <div className="hero">
      <form className="hero-card" onSubmit={submit}>
        <div className="hero-brand">
          <Logo />
          <h1>{t("unlock.title")}</h1>
          <p>{mode === "password" ? t("unlock.subtitle") : t("unlock.recoverySubtitle")}</p>
        </div>
        {mode === "password" ? (
          <PasswordField
            key="password"
            label={t("field.masterPassword")}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            autoFocus
            large
          />
        ) : (
          <TextField
            key="recovery"
            label={t("field.recoveryKey")}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={t("unlock.recoveryPlaceholder")}
            className="mono"
            autoFocus
            large
          />
        )}
        {lockedByTimer && !error ? (
          <Notice tone="accent" icon="lock">
            {t("unlock.lockedByTimer")}
          </Notice>
        ) : null}
        {error ? (
          <Notice tone="danger" icon="alert">
            {error}
          </Notice>
        ) : null}
        <Button type="submit" variant="primary" size="lg" block busy={busy} disabled={!secret}>
          {busy ? t("unlock.working") : t("unlock.submit")}
        </Button>
        <div className="hero-footer">
          <button type="button" className="link-btn" onClick={switchMode}>
            {mode === "password" ? t("unlock.useRecovery") : t("unlock.usePassword")}
          </button>
        </div>
      </form>
    </div>
  );
}
