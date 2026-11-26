// First start: create a vault, or set this device up from an existing
// account. The recovery key is shown exactly once.

import { useState, type FormEvent } from "react";
import { Button, IconButton, Notice, PasswordField, TextField } from "../components/controls";
import { Icon, Logo } from "../components/Icon";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";

type Step = "welcome" | "create" | "recovery" | "enroll";

const MIN_CHARS = 12;

export function Onboarding() {
  const { t } = useI18n();
  const [step, setStep] = useState<Step>("welcome");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);

  if (step === "create") {
    return (
      <CreateVault
        onBack={() => setStep("welcome")}
        onCreated={(key) => {
          setRecoveryKey(key);
          setStep("recovery");
        }}
      />
    );
  }
  if (step === "recovery" && recoveryKey) {
    return <RecoveryKeyStep recoveryKey={recoveryKey} />;
  }
  if (step === "enroll") {
    return <EnrollDevice onBack={() => setStep("welcome")} />;
  }
  return (
    <div className="hero">
      <div className="hero-card">
        <div className="hero-brand">
          <Logo />
          <h1>{t("onboarding.welcome.title")}</h1>
          <p>{t("onboarding.welcome.subtitle")}</p>
        </div>
        <div className="hero-actions">
          <button type="button" className="choice" onClick={() => setStep("create")}>
            <span className="choice-icon">
              <Icon name="shield" />
            </span>
            <span>
              <strong>{t("onboarding.welcome.create")}</strong>
              <span>{t("onboarding.welcome.createHint")}</span>
            </span>
          </button>
          <button type="button" className="choice" onClick={() => setStep("enroll")}>
            <span className="choice-icon">
              <Icon name="devices" />
            </span>
            <span>
              <strong>{t("onboarding.welcome.enroll")}</strong>
              <span>{t("onboarding.welcome.enrollHint")}</span>
            </span>
          </button>
        </div>
        <div className="hero-footer">
          <Icon name="lock" width={14} height={14} />
          <span>{t("onboarding.welcome.footer")}</span>
        </div>
      </div>
    </div>
  );
}

function CreateVault({ onBack, onCreated }: { onBack: () => void; onCreated: (key: string) => void }) {
  const { t } = useI18n();
  const { backend, status, errorText } = useApp();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [deviceName, setDeviceName] = useState(status.defaultDeviceName);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tooShort = password.length > 0 && Array.from(password).length < MIN_CHARS;
  const mismatch = confirmation.length > 0 && confirmation !== password;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const key = await backend.createVault(password, confirmation, deviceName);
      setPassword("");
      setConfirmation("");
      onCreated(key);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="hero">
      <form className="hero-card" onSubmit={submit}>
        <IconButton icon="arrowLeft" label={t("action.back")} className="back-btn" onClick={onBack} />
        <div>
          <h2>{t("onboarding.create.title")}</h2>
          <p className="muted">{t("onboarding.create.subtitle")}</p>
        </div>
        <PasswordField
          label={t("field.masterPassword")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={t("onboarding.create.passwordHint", { min: MIN_CHARS })}
          error={tooShort ? t("error.weak_master_password") : null}
          autoFocus
          large
        />
        <PasswordField
          label={t("field.confirmMasterPassword")}
          value={confirmation}
          onChange={(e) => setConfirmation(e.target.value)}
          error={mismatch ? t("error.password_mismatch") : null}
          large
        />
        <TextField
          label={t("field.deviceName")}
          value={deviceName}
          onChange={(e) => setDeviceName(e.target.value)}
          hint={t("onboarding.create.deviceHint")}
          maxLength={64}
        />
        <Notice tone="warning" icon="alert">
          {t("onboarding.create.warning")}
        </Notice>
        {error ? <Notice tone="danger" icon="alert">{error}</Notice> : null}
        <Button
          type="submit"
          variant="primary"
          size="lg"
          block
          busy={busy}
          disabled={Array.from(password).length < MIN_CHARS || password !== confirmation || !deviceName.trim()}
        >
          {busy ? t("onboarding.create.deriving") : t("onboarding.create.submit")}
        </Button>
      </form>
    </div>
  );
}

/** The vault is already created and unlocked; continuing opens it. */
function RecoveryKeyStep({ recoveryKey }: { recoveryKey: string }) {
  const { t } = useI18n();
  const { backend, refreshStatus, toast, errorText } = useApp();
  const [saved, setSaved] = useState(false);

  const copy = async () => {
    try {
      const r = await backend.copyText(recoveryKey);
      toast(t("toast.copied", { seconds: r.clearsInSeconds }));
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  return (
    <div className="hero">
      <div className="hero-card wide">
        <div className="hero-brand">
          <div className="dialog-icon">
            <Icon name="key" />
          </div>
          <h2>{t("onboarding.recovery.title")}</h2>
          <p>{t("onboarding.recovery.subtitle")}</p>
        </div>
        <div className="recovery-key" data-testid="recovery-key">
          {recoveryKey}
        </div>
        <div className="generator-actions">
          <Button icon="copy" onClick={copy}>
            {t("action.copy")}
          </Button>
        </div>
        <Notice tone="warning" icon="alert">
          {t("onboarding.recovery.warning")}
        </Notice>
        <label className="checkbox">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          <span>{t("onboarding.recovery.confirm")}</span>
        </label>
        <Button
          variant="primary"
          size="lg"
          block
          disabled={!saved}
          onClick={() => void refreshStatus()}
        >
          {t("onboarding.recovery.continue")}
        </Button>
      </div>
    </div>
  );
}

function EnrollDevice({ onBack }: { onBack: () => void }) {
  const { t, tn } = useI18n();
  const { backend, status, refreshStatus, toast, errorText } = useApp();
  const [server, setServer] = useState("https://");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [deviceName, setDeviceName] = useState(status.defaultDeviceName);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const received = await backend.enrollDevice(server.trim(), email.trim(), password, deviceName);
      setPassword("");
      toast(tn("onboarding.enroll.done", received));
      await refreshStatus();
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <div className="hero">
      <form className="hero-card" onSubmit={submit}>
        <IconButton icon="arrowLeft" label={t("action.back")} className="back-btn" onClick={onBack} />
        <div>
          <h2>{t("onboarding.enroll.title")}</h2>
          <p className="muted">{t("onboarding.enroll.subtitle")}</p>
        </div>
        <TextField
          label={t("field.server")}
          value={server}
          onChange={(e) => setServer(e.target.value)}
          icon="cloud"
          inputMode="url"
          autoFocus
        />
        <TextField
          label={t("field.email")}
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <PasswordField
          label={t("field.masterPassword")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <TextField
          label={t("field.deviceName")}
          value={deviceName}
          onChange={(e) => setDeviceName(e.target.value)}
          maxLength={64}
        />
        {error ? <Notice tone="danger" icon="alert">{error}</Notice> : null}
        <Button
          type="submit"
          variant="primary"
          size="lg"
          block
          busy={busy}
          disabled={!server.trim() || !email.trim() || !password || !deviceName.trim()}
        >
          {busy ? t("onboarding.enroll.working") : t("onboarding.enroll.submit")}
        </Button>
      </form>
    </div>
  );
}
