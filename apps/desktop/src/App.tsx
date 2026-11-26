import { useCallback, useEffect, useState } from "react";
import type { Backend } from "./api/backend";
import type { AppStatus, Settings } from "./api/types";
import { Logo } from "./components/Icon";
import { I18nProvider, makeI18n, resolveLocale } from "./i18n";
import { Onboarding } from "./screens/Onboarding";
import { Shell } from "./screens/Shell";
import { Unlock } from "./screens/Unlock";
import { AppProvider } from "./state/app";

function applyTheme(theme: Settings["theme"]) {
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
}

export function App({ backend }: { backend: Backend }) {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [lockedByTimer, setLockedByTimer] = useState(false);

  const refreshStatus = useCallback(async () => {
    const next = await backend.appStatus();
    setStatus(next);
    if (next.unlocked) setLockedByTimer(false);
  }, [backend]);

  useEffect(() => {
    void Promise.all([backend.appStatus(), backend.getSettings()]).then(([s, prefs]) => {
      setStatus(s);
      setSettings(prefs);
    });
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void backend
      .onLocked(() => {
        setLockedByTimer(true);
        setStatus((s) => (s ? { ...s, unlocked: false } : s));
      })
      .then((fn) => {
        // The effect may already be cleaned up (strict mode, unmount).
        if (disposed) fn();
        else unlisten = fn;
      });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [backend]);

  const updateSettings = useCallback(
    async (next: Settings) => {
      setSettings(await backend.setSettings(next));
    },
    [backend],
  );

  const locale = resolveLocale(settings?.language ?? "system", navigator.language);

  useEffect(() => {
    if (settings) applyTheme(settings.theme);
  }, [settings]);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.title = makeI18n(locale).t("app.name");
  }, [locale]);

  if (!status || !settings) {
    return (
      <div className="hero">
        <div className="hero-brand">
          <Logo />
        </div>
      </div>
    );
  }

  return (
    <I18nProvider locale={locale}>
      <AppProvider
        backend={backend}
        status={status}
        settings={settings}
        refreshStatus={refreshStatus}
        updateSettings={updateSettings}
      >
        {!status.vaultExists ? (
          <Onboarding />
        ) : !status.unlocked ? (
          <Unlock lockedByTimer={lockedByTimer} />
        ) : (
          <Shell />
        )}
      </AppProvider>
    </I18nProvider>
  );
}
