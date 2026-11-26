// The unlocked application: navigation, automatic synchronization, activity
// reporting (auto-lock runs in Rust) and keyboard shortcuts.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isUiError, type ItemKind, type ItemSummary, type VaultInfo } from "../api/types";
import { Button, IconButton } from "../components/controls";
import { Dialog } from "../components/Dialog";
import { Icon, Logo, type IconName } from "../components/Icon";
import { useI18n, type MessageKey } from "../i18n";
import { errorKey, useApp } from "../state/app";
import { Devices } from "./Devices";
import { Generator } from "./Generator";
import { SettingsPage } from "./SettingsPage";
import { VaultView } from "./VaultView";

export type Filter = "all" | "favorites" | ItemKind;

export type View =
  | { kind: "vault"; filter: Filter }
  | { kind: "generator" }
  | { kind: "devices" }
  | { kind: "settings" };

export interface SyncState {
  phase: "idle" | "syncing" | "ok" | "error";
  at: number | null;
  error: MessageKey | null;
}

export interface SyncControl {
  info: VaultInfo | null;
  state: SyncState;
  syncNow: (reset?: boolean) => Promise<void>;
  /** Synchronize soon after a local change. */
  schedule: () => void;
  reloadInfo: () => Promise<void>;
}

const ACTIVITY_THROTTLE_MS = 15_000;
const SYNC_INTERVAL_MS = 5 * 60_000;
const SYNC_DEBOUNCE_MS = 1_500;

function useSync(onChanged: () => void): SyncControl & { rollback: boolean; dismissRollback: () => void } {
  const { backend, toast } = useApp();
  const { t, tn } = useI18n();
  const [info, setInfo] = useState<VaultInfo | null>(null);
  const [state, setState] = useState<SyncState>({ phase: "idle", at: null, error: null });
  const [rollback, setRollback] = useState(false);
  const running = useRef(false);
  const timer = useRef<number | undefined>(undefined);
  const registered = info?.remote != null;

  const reloadInfo = useCallback(async () => {
    setInfo(await backend.vaultInfo());
  }, [backend]);

  const syncNow = useCallback(
    async (reset = false) => {
      if (!registered || running.current) return;
      running.current = true;
      setState((s) => ({ ...s, phase: "syncing" }));
      try {
        const summary = await backend.sync(reset);
        setState({ phase: "ok", at: Math.floor(Date.now() / 1000), error: null });
        setRollback(false);
        if (summary.received > 0 || summary.conflictCopies > 0 || reset) onChanged();
        if (summary.conflictCopies > 0) toast(tn("sync.conflictCopies", summary.conflictCopies));
        else if (reset) toast(t("sync.resetDone"));
        void reloadInfo();
      } catch (err) {
        setState((s) => ({ ...s, phase: "error", error: errorKey(err) }));
        if (isUiError(err) && err.kind === "server_rollback") setRollback(true);
      } finally {
        running.current = false;
      }
    },
    [backend, registered, onChanged, reloadInfo, toast, t, tn],
  );

  const schedule = useCallback(() => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => void syncNow(), SYNC_DEBOUNCE_MS);
  }, [syncNow]);

  useEffect(() => {
    void reloadInfo();
  }, [reloadInfo]);

  // Synchronize once unlocked, then periodically.
  useEffect(() => {
    if (!registered) return;
    void syncNow();
    const id = window.setInterval(() => void syncNow(), SYNC_INTERVAL_MS);
    return () => {
      window.clearInterval(id);
      window.clearTimeout(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per registration
  }, [registered]);

  return {
    info,
    state,
    syncNow,
    schedule,
    reloadInfo,
    rollback,
    dismissRollback: () => setRollback(false),
  };
}

function useActivity() {
  const { backend } = useApp();
  useEffect(() => {
    let last = 0;
    const report = () => {
      const now = Date.now();
      if (now - last < ACTIVITY_THROTTLE_MS) return;
      last = now;
      void backend.touch().catch(() => undefined);
    };
    const events = ["pointerdown", "keydown", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, report, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, report));
  }, [backend]);
}

const NAV: { filter: Filter; icon: IconName; label: MessageKey }[] = [
  { filter: "all", icon: "grid", label: "nav.all" },
  { filter: "favorites", icon: "star", label: "nav.favorites" },
  { filter: "login", icon: "globe", label: "nav.logins" },
  { filter: "secure_note", icon: "note", label: "nav.notes" },
  { filter: "payment_card", icon: "card", label: "nav.cards" },
  { filter: "identity", icon: "identity", label: "nav.identities" },
];

function matches(item: ItemSummary, filter: Filter): boolean {
  if (filter === "all") return true;
  if (filter === "favorites") return item.favorite;
  return item.kind === filter;
}

export function Shell() {
  const { t } = useI18n();
  const { backend, refreshStatus, errorText, toast } = useApp();
  const [view, setView] = useState<View>({ kind: "vault", filter: "all" });
  const [version, setVersion] = useState(0);
  const [all, setAll] = useState<ItemSummary[]>([]);
  const changed = useCallback(() => setVersion((v) => v + 1), []);
  const sync = useSync(changed);
  useActivity();

  useEffect(() => {
    backend
      .listItems("")
      .then(setAll)
      .catch((err: unknown) => toast(errorText(err), "error"));
  }, [backend, version, errorText, toast]);

  const counts = useMemo(() => {
    const result: Record<Filter, number> = {
      all: 0,
      favorites: 0,
      login: 0,
      secure_note: 0,
      payment_card: 0,
      identity: 0,
    };
    for (const item of all) {
      for (const n of NAV) if (matches(item, n.filter)) result[n.filter] += 1;
    }
    return result;
  }, [all]);

  const lock = useCallback(async () => {
    await backend.lock();
    await refreshStatus();
  }, [backend, refreshStatus]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.key.toLowerCase() === "l") {
        e.preventDefault();
        void lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  const localChange = useCallback(() => {
    changed();
    sync.schedule();
  }, [changed, sync]);

  return (
    <div className="shell">
      <nav className="sidebar" aria-label={t("nav.label")}>
        <div className="sidebar-brand">
          <Logo />
          <span>{t("app.name")}</span>
        </div>
        <div className="nav-section">{t("nav.vault")}</div>
        {NAV.map((n) => (
          <button
            key={n.filter}
            type="button"
            className="nav-item"
            aria-current={view.kind === "vault" && view.filter === n.filter ? "page" : undefined}
            onClick={() => setView({ kind: "vault", filter: n.filter })}
            title={t(n.label)}
          >
            <Icon name={n.icon} />
            <span className="label">{t(n.label)}</span>
            <span className="count">{counts[n.filter]}</span>
          </button>
        ))}
        <div className="nav-section">{t("nav.tools")}</div>
        <button
          type="button"
          className="nav-item"
          aria-current={view.kind === "generator" ? "page" : undefined}
          onClick={() => setView({ kind: "generator" })}
          title={t("nav.generator")}
        >
          <Icon name="wand" />
          <span className="label">{t("nav.generator")}</span>
        </button>
        <button
          type="button"
          className="nav-item"
          aria-current={view.kind === "devices" ? "page" : undefined}
          onClick={() => setView({ kind: "devices" })}
          title={t("nav.devices")}
        >
          <Icon name="devices" />
          <span className="label">{t("nav.devices")}</span>
        </button>
        <button
          type="button"
          className="nav-item"
          aria-current={view.kind === "settings" ? "page" : undefined}
          onClick={() => setView({ kind: "settings" })}
          title={t("nav.settings")}
        >
          <Icon name="settings" />
          <span className="label">{t("nav.settings")}</span>
        </button>
        <div className="sidebar-spacer" />
        <SyncStatus sync={sync} onOpenSettings={() => setView({ kind: "settings" })} />
        <button type="button" className="nav-item" onClick={() => void lock()} title={t("nav.lock")}>
          <Icon name="lock" />
          <span className="label">{t("nav.lock")}</span>
        </button>
      </nav>
      <main className="main">
        {view.kind === "vault" ? (
          <VaultView
            filter={view.filter}
            matches={(item) => matches(item, view.filter)}
            version={version}
            onLocalChange={localChange}
          />
        ) : view.kind === "generator" ? (
          <Generator />
        ) : view.kind === "devices" ? (
          <Devices sync={sync} onOpenSettings={() => setView({ kind: "settings" })} />
        ) : (
          <SettingsPage sync={sync} onVaultChanged={changed} />
        )}
      </main>
      {sync.rollback ? (
        <Dialog
          title={t("rollback.title")}
          icon="alert"
          danger
          onClose={sync.dismissRollback}
          actions={
            <>
              <Button variant="ghost" onClick={sync.dismissRollback}>
                {t("action.notNow")}
              </Button>
              <Button
                variant="primary"
                icon="sync"
                onClick={() => {
                  sync.dismissRollback();
                  void sync.syncNow(true);
                }}
              >
                {t("rollback.reset")}
              </Button>
            </>
          }
        >
          <p className="muted">{t("rollback.text")}</p>
          <p className="muted">{t("rollback.warning")}</p>
        </Dialog>
      ) : null}
    </div>
  );
}

function SyncStatus({ sync, onOpenSettings }: { sync: SyncControl; onOpenSettings: () => void }) {
  const { t, time } = useI18n();
  if (!sync.info) return null;
  if (!sync.info.remote) {
    return (
      <button type="button" className="nav-item" onClick={onOpenSettings} title={t("sync.localOnly")}>
        <Icon name="cloud" />
        <span className="label">{t("sync.localOnly")}</span>
      </button>
    );
  }
  const { phase, at, error } = sync.state;
  return (
    <div className={`sync-status ${phase === "error" ? "error" : ""}`} role="status">
      {phase === "syncing" ? <span className="spinner" style={{ width: 14, height: 14 }} /> : (
        <Icon name={phase === "error" ? "alert" : "sync"} />
      )}
      <span className="label">
        {phase === "syncing"
          ? t("sync.running")
          : phase === "error" && error
            ? t(error)
            : at
              ? t("sync.doneAt", { time: time(at) })
              : t("sync.ready")}
      </span>
      {phase !== "syncing" ? (
        <IconButton icon="sync" label={t("sync.now")} onClick={() => void sync.syncNow()} />
      ) : null}
    </div>
  );
}
