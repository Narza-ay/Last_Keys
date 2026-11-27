// Settings section: browser extension (ADR-0011). Turning it on registers
// the native messaging host with the installed browsers and serves the
// local endpoint; paired extensions are listed and can be revoked.

import { useEffect, useState } from "react";
import type { BridgeStatus, BrowserName, InstallState } from "../api/types";
import { Button, Notice, Toggle } from "../components/controls";
import { useI18n, type MessageKey } from "../i18n";
import { useApp } from "../state/app";

const BROWSER_LABEL: Record<BrowserName, string> = {
  chrome: "Google Chrome",
  chromium: "Chromium",
  brave: "Brave",
  firefox: "Firefox",
};

const STATE_KEY: Record<InstallState, MessageKey> = {
  installed: "browser.state.installed",
  not_detected: "browser.state.notDetected",
  not_installed: "browser.state.notInstalled",
  failed: "browser.state.failed",
};

const STATE_BADGE: Record<InstallState, string> = {
  installed: "badge badge-success",
  not_detected: "badge",
  not_installed: "badge badge-warning",
  failed: "badge badge-danger",
};

export function BrowserIntegration() {
  const { t, date } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [status, setStatus] = useState<BridgeStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let disposed = false;
    const load = () =>
      backend
        .bridgeStatus()
        .then((next) => {
          if (!disposed) setStatus(next);
        })
        .catch((err: unknown) => toast(errorText(err), "error"));
    void load();
    const unlisten: (() => void)[] = [];
    const keep = (fn: () => void) => (disposed ? fn() : unlisten.push(fn));
    // A pairing changes the list of connected browsers.
    void backend.onPairingClosed(() => void load()).then(keep);
    return () => {
      disposed = true;
      unlisten.forEach((fn) => fn());
    };
  }, [backend, errorText, toast]);

  const toggle = async (enabled: boolean) => {
    setBusy(true);
    try {
      setStatus(await backend.setBrowserIntegration(enabled));
    } catch (err) {
      toast(errorText(err), "error");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (clientId: string) => {
    try {
      setStatus(await backend.revokeBrowser(clientId));
      toast(t("browser.revoked"));
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  if (!status) return <div className="card card-section" aria-busy="true" />;

  return (
    <div className="card">
      <div className="settings-row">
        <div className="settings-row-text">
          <strong>{t("browser.enable")}</strong>
          <span>{t("browser.enableHint")}</span>
        </div>
        <Toggle
          label={status.enabled ? t("browser.on") : t("browser.off")}
          checked={status.enabled}
          disabled={busy}
          onChange={(enabled) => void toggle(enabled)}
        />
      </div>
      {status.enabled && status.error ? (
        <div className="card-section">
          <Notice tone="warning" icon="alert">
            {status.error === "in_use" ? t("browser.errorInUse") : t("browser.errorUnavailable")}
          </Notice>
        </div>
      ) : null}
      {status.enabled ? (
        <>
          <div className="settings-row">
            <div className="settings-row-text">
              <strong>{t("browser.browsers")}</strong>
              <span>{t("browser.browsersHint")}</span>
            </div>
            <ul className="browser-list" aria-label={t("browser.browsers")}>
              {status.browsers.map((b) => (
                <li key={b.browser}>
                  <span>{BROWSER_LABEL[b.browser]}</span>
                  <span className={STATE_BADGE[b.state]}>{t(STATE_KEY[b.state])}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="settings-row settings-row-stacked">
            <div className="settings-row-text">
              <strong>{t("browser.paired")}</strong>
              <span>{status.clients.length === 0 ? t("browser.pairedEmpty") : t("browser.pairedHint")}</span>
            </div>
            {status.clients.length > 0 ? (
              <ul className="paired-list" aria-label={t("browser.paired")}>
                {status.clients.map((c) => (
                  <li key={c.clientId}>
                    <div className="paired-text">
                      <strong>{c.name}</strong>
                      <span className="muted">
                        {c.lastUsedAt
                          ? t("browser.lastUsed", { date: date(c.lastUsedAt) })
                          : t("browser.pairedOn", { date: date(c.createdAt) })}
                      </span>
                    </div>
                    <Button variant="ghost" icon="trash" onClick={() => void revoke(c.clientId)}>
                      {t("browser.revoke")}
                    </Button>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </>
      ) : null}
    </div>
  );
}
