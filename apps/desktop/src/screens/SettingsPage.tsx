// Preferences, account and synchronization, master password, recovery key,
// information about this vault.

import { useState, type FormEvent, type ReactNode } from "react";
import type { Language, Settings, Theme } from "../api/types";
import { Button, Notice, PasswordField, Segmented, Select, TextField } from "../components/controls";
import { Dialog } from "../components/Dialog";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";
import type { SyncControl } from "./Shell";

function Row({ title, text, children }: { title: string; text?: string; children: ReactNode }) {
  return (
    <div className="settings-row">
      <div className="settings-row-text">
        <strong>{title}</strong>
        {text ? <span>{text}</span> : null}
      </div>
      <div>{children}</div>
    </div>
  );
}

export function SettingsPage({ sync, onVaultChanged }: { sync: SyncControl; onVaultChanged: () => void }) {
  const { t, tn } = useI18n();
  const { settings, updateSettings, errorText, toast } = useApp();
  const info = sync.info;

  const save = async (patch: Partial<Settings>) => {
    try {
      await updateSettings({ ...settings, ...patch });
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-header">
          <h1>{t("settings.title")}</h1>
        </header>

        <div className="section-title">{t("settings.appearance")}</div>
        <div className="card">
          <Row title={t("settings.language")}>
            <Select
              hideLabel
              label={t("settings.language")}
              value={settings.language}
              onChange={(e) => void save({ language: e.target.value as Language })}
              options={[
                { value: "system", label: t("settings.languageSystem") },
                { value: "fr", label: "Français" },
                { value: "en", label: "English" },
              ]}
            />
          </Row>
          <Row title={t("settings.theme")}>
            <Segmented<Theme>
              label={t("settings.theme")}
              value={settings.theme}
              onChange={(theme) => void save({ theme })}
              options={[
                { value: "system", label: t("settings.themeSystem") },
                { value: "light", label: t("settings.themeLight") },
                { value: "dark", label: t("settings.themeDark") },
              ]}
            />
          </Row>
        </div>

        <div className="section-title">{t("settings.security")}</div>
        <div className="card">
          <Row title={t("settings.autoLock")} text={t("settings.autoLockHint")}>
            <Select
              hideLabel
              label={t("settings.autoLock")}
              value={String(settings.autoLockMinutes)}
              onChange={(e) => void save({ autoLockMinutes: Number(e.target.value) })}
              options={[1, 2, 5, 10, 15, 30, 60, 120, 240].map((m) => ({
                value: String(m),
                label: tn("settings.minutes", m),
              }))}
            />
          </Row>
          <Row title={t("settings.clipboard")} text={t("settings.clipboardHint")}>
            <Select
              hideLabel
              label={t("settings.clipboard")}
              value={String(settings.clipboardClearSeconds)}
              onChange={(e) => void save({ clipboardClearSeconds: Number(e.target.value) })}
              options={[10, 20, 30, 60, 120, 300].map((s) => ({
                value: String(s),
                label: tn("settings.seconds", s),
              }))}
            />
          </Row>
        </div>

        <div className="section-title">{t("settings.account")}</div>
        <div className="card">
          {info?.remote ? (
            <SyncSettings sync={sync} onVaultChanged={onVaultChanged} />
          ) : (
            <RegisterForm sync={sync} onVaultChanged={onVaultChanged} />
          )}
        </div>

        <div className="section-title">{t("settings.masterPassword")}</div>
        <div className="card card-section">
          <MasterPasswordForm resetting={info?.unlockedWith === "recovery_key"} onDone={() => void sync.reloadInfo()} />
        </div>

        <div className="section-title">{t("settings.recoveryKey")}</div>
        <div className="card">
          <RecoveryKeyRotation disabled={info?.unlockedWith === "recovery_key"} />
        </div>

        <div className="section-title">{t("settings.about")}</div>
        <div className="card">
          {info ? (
            <>
              <Row title={t("settings.device")}>
                <span className="muted selectable">{info.deviceName}</span>
              </Row>
              <Row title={t("settings.accountId")}>
                <span className="muted mono selectable">{info.accountId.slice(0, 8)}</span>
              </Row>
              <Row title={t("settings.kdf")}>
                <span className="muted">
                  {t("settings.kdfValue", {
                    memory: Math.round(info.kdf.memoryKib / 1024),
                    passes: info.kdf.iterations,
                    lanes: info.kdf.parallelism,
                  })}
                </span>
              </Row>
              <Row title={t("settings.protection")} text={t("settings.protectionText")}>
                <span className="badge badge-warning">{t("settings.protectionSoftware")}</span>
              </Row>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function RegisterForm({ sync, onVaultChanged }: { sync: SyncControl; onVaultChanged: () => void }) {
  const { t, tn } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [server, setServer] = useState("https://");
  const [email, setEmail] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const summary = await backend.register(server.trim(), email.trim(), recoveryKey);
      setRecoveryKey("");
      toast(tn("settings.registered", summary.sent));
      await sync.reloadInfo();
      onVaultChanged();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card-section form" onSubmit={submit}>
      <p className="muted">{t("settings.registerIntro")}</p>
      <div className="grid-2">
        <TextField label={t("field.server")} value={server} onChange={(e) => setServer(e.target.value)} icon="cloud" inputMode="url" />
        <TextField label={t("field.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </div>
      <TextField
        label={t("field.recoveryKey")}
        hint={t("settings.registerRecoveryHint")}
        value={recoveryKey}
        onChange={(e) => setRecoveryKey(e.target.value)}
        className="mono"
        placeholder={t("unlock.recoveryPlaceholder")}
      />
      {error ? (
        <Notice tone="danger" icon="alert">
          {error}
        </Notice>
      ) : null}
      <div>
        <Button type="submit" variant="primary" icon="cloud" busy={busy} disabled={!server.trim() || !email.trim() || !recoveryKey.trim()}>
          {t("settings.register")}
        </Button>
      </div>
    </form>
  );
}

function SyncSettings({ sync, onVaultChanged }: { sync: SyncControl; onVaultChanged: () => void }) {
  const { t, dateTime } = useI18n();
  const [confirmReset, setConfirmReset] = useState(false);
  const remote = sync.info?.remote;
  if (!remote) return null;
  return (
    <>
      <Row title={t("field.server")}>
        <span className="muted selectable">{remote.server}</span>
      </Row>
      <Row title={t("field.email")}>
        <span className="muted selectable">{remote.email}</span>
      </Row>
      <Row
        title={t("settings.lastSync")}
        text={
          sync.state.phase === "error" && sync.state.error
            ? t(sync.state.error)
            : sync.state.at
              ? dateTime(sync.state.at)
              : t("sync.ready")
        }
      >
        <Button icon="sync" busy={sync.state.phase === "syncing"} onClick={() => void sync.syncNow().then(onVaultChanged)}>
          {t("sync.now")}
        </Button>
      </Row>
      <Row title={t("settings.fullResync")} text={t("settings.fullResyncHint")}>
        <Button variant="secondary" onClick={() => setConfirmReset(true)}>
          {t("rollback.reset")}
        </Button>
      </Row>
      {confirmReset ? (
        <Dialog
          title={t("settings.fullResync")}
          icon="sync"
          onClose={() => setConfirmReset(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirmReset(false)}>
                {t("action.cancel")}
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setConfirmReset(false);
                  void sync.syncNow(true).then(onVaultChanged);
                }}
              >
                {t("rollback.reset")}
              </Button>
            </>
          }
        >
          <p className="muted">{t("rollback.warning")}</p>
        </Dialog>
      ) : null}
    </>
  );
}

function MasterPasswordForm({ resetting, onDone }: { resetting: boolean; onDone: () => void }) {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await backend.changeMasterPassword(resetting ? null : current, password, confirmation);
      setCurrent("");
      setPassword("");
      setConfirmation("");
      toast(t("settings.passwordChanged"));
      onDone();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form" onSubmit={submit}>
      {resetting ? (
        <Notice tone="accent" icon="key">
          {t("settings.resetNotice")}
        </Notice>
      ) : (
        <PasswordField label={t("field.currentPassword")} value={current} onChange={(e) => setCurrent(e.target.value)} />
      )}
      <div className="grid-2">
        <PasswordField
          label={t("field.newPassword")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={t("onboarding.create.passwordHint", { min: 12 })}
        />
        <PasswordField
          label={t("field.confirmMasterPassword")}
          value={confirmation}
          onChange={(e) => setConfirmation(e.target.value)}
          error={confirmation && confirmation !== password ? t("error.password_mismatch") : null}
        />
      </div>
      {error ? (
        <Notice tone="danger" icon="alert">
          {error}
        </Notice>
      ) : null}
      <div>
        <Button type="submit" variant="primary" busy={busy} disabled={(!resetting && !current) || !password || password !== confirmation}>
          {t("settings.changePassword")}
        </Button>
      </div>
    </form>
  );
}

function RecoveryKeyRotation({ disabled }: { disabled: boolean }) {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [asking, setAsking] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const close = () => {
    setAsking(false);
    setPassword("");
    setError(null);
  };

  return (
    <>
      <Row title={t("settings.rotateRecovery")} text={t("settings.rotateRecoveryHint")}>
        <Button onClick={() => setAsking(true)} disabled={disabled}>
          {t("settings.rotate")}
        </Button>
      </Row>
      {asking ? (
        <Dialog
          title={t("settings.rotateRecovery")}
          icon="key"
          onClose={close}
          actions={
            <>
              <Button variant="ghost" onClick={close}>
                {t("action.cancel")}
              </Button>
              <Button
                variant="primary"
                busy={busy}
                disabled={!password}
                onClick={async () => {
                  setBusy(true);
                  setError(null);
                  try {
                    const key = await backend.rotateRecoveryKey(password);
                    close();
                    setSaved(false);
                    setNewKey(key);
                  } catch (err) {
                    setError(errorText(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t("settings.rotate")}
              </Button>
            </>
          }
        >
          <p className="muted">{t("settings.rotateConfirmText")}</p>
          <PasswordField label={t("field.currentPassword")} value={password} onChange={(e) => setPassword(e.target.value)} />
          {error ? (
            <Notice tone="danger" icon="alert">
              {error}
            </Notice>
          ) : null}
        </Dialog>
      ) : null}
      {newKey ? (
        <Dialog
          title={t("onboarding.recovery.title")}
          icon="key"
          onClose={() => undefined}
          actions={
            <Button variant="primary" disabled={!saved} onClick={() => setNewKey(null)}>
              {t("action.done")}
            </Button>
          }
        >
          <p className="muted">{t("onboarding.recovery.subtitle")}</p>
          <div className="recovery-key">{newKey}</div>
          <div className="generator-actions">
            <Button
              icon="copy"
              onClick={async () => {
                try {
                  const r = await backend.copyText(newKey);
                  toast(t("toast.copied", { seconds: r.clearsInSeconds }));
                } catch (err) {
                  toast(errorText(err), "error");
                }
              }}
            >
              {t("action.copy")}
            </Button>
          </div>
          <label className="checkbox">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            <span>{t("onboarding.recovery.confirm")}</span>
          </label>
        </Dialog>
      ) : null}
    </>
  );
}
