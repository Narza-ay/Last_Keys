// The extension's popup: connection state, the logins of the active page,
// credentials waiting to be saved, and the password generator.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ConnectionState, CopyField, FillResult, Login, PageView } from "../shared/messages";
import type { PopupApi } from "./api";
import { errorKey, localeOf, translator, type Key, type Translate } from "./i18n";

type Notice = { tone: "info" | "error"; text: string } | null;

interface Confirm {
  login: Login;
  frameId: number;
  frameHost: string;
}

function Logo() {
  return <img className="logo" src="logo.svg" alt="" width={28} height={28} />;
}

function Status({
  t,
  conn,
  onRetry,
  onConnect,
  onUnlock,
}: {
  t: Translate;
  conn: ConnectionState;
  onRetry: () => void;
  onConnect: () => void;
  onUnlock: () => void;
}) {
  if (conn.state === "unavailable") {
    return (
      <section className="state" aria-live="polite">
        <h2>{t("status.unavailable.title")}</h2>
        <p>{t("status.unavailable.text")}</p>
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          {t("status.retry")}
        </button>
      </section>
    );
  }
  if (conn.state === "unpaired") {
    return (
      <section className="state" aria-live="polite">
        <h2>{t("status.unpaired.title")}</h2>
        <p>{t("status.unpaired.text")}</p>
        {conn.refused ? <p className="notice notice-error">{t(`status.refused.${conn.refused}` as Key)}</p> : null}
        <button type="button" className="btn btn-primary" onClick={onConnect}>
          {t("status.connect")}
        </button>
      </section>
    );
  }
  if (conn.state === "pairing") {
    return (
      <section className="state" aria-live="polite">
        <h2>{t("status.pairing.title")}</h2>
        <p className="code" data-testid="pairing-code">
          {conn.code}
        </p>
        <p>{t("status.pairing.text")}</p>
      </section>
    );
  }
  return (
    <section className="state" aria-live="polite">
      <h2>{t("status.locked.title")}</h2>
      <p>{t("status.locked.text")}</p>
      <button type="button" className="btn btn-primary" onClick={onUnlock}>
        {t("status.unlock")}
      </button>
    </section>
  );
}

export function Popup({ api }: { api: PopupApi }) {
  const t = useMemo(() => translator(localeOf(api.language())), [api]);
  const [conn, setConn] = useState<ConnectionState | null>(null);
  const [page, setPage] = useState<PageView | null>(null);
  const [tabId, setTabId] = useState<number | undefined>(undefined);
  const [notice, setNotice] = useState<Notice>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [generated, setGenerated] = useState<string | null>(null);

  const fail = useCallback((code: string) => setNotice({ tone: "error", text: t(errorKey(code)) }), [t]);

  const load = useCallback(async () => {
    const id = await api.activeTabId();
    setTabId(id);
    const state = await api.request<ConnectionState>({ kind: "state" });
    if (!state.ok) {
      setConn({ state: "unavailable" });
      return;
    }
    setConn(state.value);
    if (state.value.state === "ready" && id !== undefined) {
      const view = await api.request<PageView>({ kind: "page", tabId: id });
      if (view.ok) setPage(view.value);
      else fail(view.code);
    } else {
      setPage(null);
    }
  }, [api, fail]);

  useEffect(() => {
    // Initial load, then again whenever the background reports a change.
    const timer = setTimeout(() => void load(), 0);
    const stop = api.onStateChanged(() => void load());
    return () => {
      clearTimeout(timer);
      stop();
    };
  }, [api, load]);

  const connect = async () => {
    setNotice(null);
    const r = await api.request<ConnectionState>({ kind: "pair" });
    if (r.ok) setConn(r.value);
    else fail(r.code);
  };

  const focus = async () => {
    const r = await api.request<null>({ kind: "focus" });
    if (!r.ok) fail(r.code);
  };

  const fill = async (login: Login, confirmFrame?: number) => {
    if (tabId === undefined) return;
    setNotice(null);
    const r = await api.request<FillResult>({
      kind: "fill",
      tabId,
      itemId: login.id,
      ...(confirmFrame !== undefined ? { confirmFrame } : {}),
    });
    if (!r.ok) return fail(r.code);
    if ("confirm" in r.value) {
      setConfirm({ login, frameId: r.value.confirm.frameId, frameHost: r.value.confirm.frameHost });
      return;
    }
    setConfirm(null);
    if (r.value.filled > 0) api.close();
    else setNotice({ tone: "info", text: t("fill.none") });
  };

  const copy = async (login: Login, field: CopyField) => {
    if (tabId === undefined) return;
    const r = await api.request<{ clearsInSeconds: number }>({ kind: "copy", tabId, itemId: login.id, field });
    if (r.ok) setNotice({ tone: "info", text: t("copy.done", { seconds: r.value.clearsInSeconds }) });
    else fail(r.code);
  };

  const save = async () => {
    if (tabId === undefined) return;
    const r = await api.request<null>({ kind: "save", tabId });
    if (!r.ok) return fail(r.code);
    setNotice({ tone: "info", text: t("save.done") });
    await load();
  };

  const dismiss = async () => {
    if (tabId === undefined) return;
    await api.request<null>({ kind: "dismissSave", tabId });
    await load();
  };

  const generate = async () => {
    const r = await api.request<{ password: string }>({ kind: "generate" });
    if (r.ok) setGenerated(r.value.password);
    else fail(r.code);
  };

  const allowDetection = async () => {
    // Firefox closes the popup while it asks; the background registers the
    // content script when the permission arrives either way.
    if (await api.requestHostAccess()) await load();
  };

  const fillGenerated = async () => {
    if (tabId === undefined || !generated) return;
    const r = await api.request<FillResult>({ kind: "fillGenerated", tabId, password: generated });
    if (!r.ok) return fail(r.code);
    if ("filled" in r.value && r.value.filled > 0) api.close();
    else setNotice({ tone: "info", text: t("fill.none") });
  };

  const ready = conn?.state === "ready" && !conn.locked;
  const pending = page?.pendingSave ?? null;

  return (
    <div className="popup">
      <header className="header">
        <Logo />
        <h1>{t("app.name")}</h1>
        {page?.host ? (
          <span className="host" title={page.host}>
            {page.host}
          </span>
        ) : null}
      </header>

      {notice ? (
        <p className={`notice ${notice.tone === "error" ? "notice-error" : ""}`} role="status">
          {notice.text}
        </p>
      ) : null}

      {conn && !ready ? (
        <Status t={t} conn={conn} onRetry={() => void load()} onConnect={() => void connect()} onUnlock={() => void focus()} />
      ) : null}

      {ready && page && !page.eligible ? <p className="empty">{t("page.ineligible")}</p> : null}

      {ready && page?.eligible ? (
        <>
          {page.internationalized ? <p className="notice notice-warning">{t("page.idn")}</p> : null}

          {!page.detection ? (
            <section className="detection" aria-label={t("detection.title")}>
              <strong>{t("detection.title")}</strong>
              <span className="muted">{t("detection.text")}</span>
              <div className="row">
                <button type="button" className="btn btn-secondary btn-small" onClick={() => void allowDetection()}>
                  {t("detection.allow")}
                </button>
              </div>
            </section>
          ) : null}

          {pending ? (
            <section className="save" aria-label={t("save.newTitle")}>
              {pending.proposal === null ? (
                <>
                  <strong>{t("save.pendingTitle", { host: pending.host })}</strong>
                  <span>{t("save.pendingText")}</span>
                </>
              ) : pending.proposal.action === "update_password" ? (
                <strong>{t("save.updateTitle", { title: pending.proposal.title })}</strong>
              ) : (
                <strong>{t("save.newTitle")}</strong>
              )}
              {pending.username ? <span className="muted">{pending.username}</span> : null}
              <div className="row">
                {pending.proposal ? (
                  <button type="button" className="btn btn-primary" onClick={() => void save()}>
                    {pending.proposal.action === "update_password" ? t("save.update") : t("save.save")}
                  </button>
                ) : null}
                <button type="button" className="btn btn-ghost" onClick={() => void dismiss()}>
                  {t("save.notNow")}
                </button>
              </div>
            </section>
          ) : null}

          {confirm ? (
            <section className="confirm" role="alertdialog" aria-label={t("fill.confirm.title")}>
              <strong>{t("fill.confirm.title")}</strong>
              <span>{t("fill.confirm.text", { host: confirm.frameHost })}</span>
              <div className="row">
                <button type="button" className="btn btn-primary" onClick={() => void fill(confirm.login, confirm.frameId)}>
                  {t("fill.confirm.yes")}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setConfirm(null)}>
                  {t("fill.confirm.no")}
                </button>
              </div>
            </section>
          ) : null}

          {page.logins.length === 0 ? (
            <div className="empty">
              <p>{t("page.none")}</p>
              <p className="muted">{t("page.noneHint")}</p>
            </div>
          ) : (
            <ul className="logins" aria-label={t("app.name")}>
              {page.logins.map((login) => (
                <li key={login.id} className="login">
                  <div className="login-text">
                    <strong>{login.title}</strong>
                    <span className="muted">{login.username ?? t("login.noUsername")}</span>
                    {login.matched === "same_site" ? <span className="tag">{t("page.sameSite")}</span> : null}
                  </div>
                  <div className="login-actions">
                    <button type="button" className="btn btn-primary btn-small" onClick={() => void fill(login)}>
                      {t("login.fill")}
                    </button>
                    {login.username ? (
                      <button
                        type="button"
                        className="btn btn-ghost btn-small"
                        onClick={() => void copy(login, "username")}
                        aria-label={`${t("login.copyUsername")} · ${login.title}`}
                      >
                        {t("login.copyUsername")}
                      </button>
                    ) : null}
                    {login.hasPassword ? (
                      <button
                        type="button"
                        className="btn btn-ghost btn-small"
                        onClick={() => void copy(login, "password")}
                        aria-label={`${t("login.copyPassword")} · ${login.title}`}
                      >
                        {t("login.copyPassword")}
                      </button>
                    ) : null}
                    {login.hasTotp ? (
                      <button
                        type="button"
                        className="btn btn-ghost btn-small"
                        onClick={() => void copy(login, "totp")}
                        aria-label={`${t("login.copyCode")} · ${login.title}`}
                      >
                        {t("login.copyCode")}
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}

          <section className="generator">
            {generated ? (
              <>
                <strong>{t("generate.title")}</strong>
                <code className="generated" data-testid="generated">
                  {generated}
                </code>
                <span className="muted">{t("generate.hint")}</span>
                <button type="button" className="btn btn-secondary" onClick={() => void fillGenerated()}>
                  {t("generate.fill")}
                </button>
              </>
            ) : (
              <button type="button" className="btn btn-secondary" onClick={() => void generate()}>
                {t("generate.button")}
              </button>
            )}
          </section>
        </>
      ) : null}

      {conn?.state === "ready" ? (
        <footer className="footer">
          <button type="button" className="btn btn-ghost btn-small" onClick={() => void focus()}>
            {t("footer.open")}
          </button>
        </footer>
      ) : null}
    </div>
  );
}
