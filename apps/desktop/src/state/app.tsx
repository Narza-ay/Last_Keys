// Application-wide state: back end, status, settings, notifications.

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import type { Backend } from "../api/backend";
import { isUiError, type AppStatus, type Settings } from "../api/types";
import { catalogues, useI18n, type MessageKey } from "../i18n";
import { Icon } from "../components/Icon";

export interface Toast {
  id: number;
  text: string;
  tone: "info" | "error";
}

export interface AppContextValue {
  backend: Backend;
  status: AppStatus;
  settings: Settings;
  refreshStatus: () => Promise<void>;
  updateSettings: (settings: Settings) => Promise<void>;
  toast: (text: string, tone?: Toast["tone"]) => void;
  /** Translated, secret-free description of a back-end error. */
  errorText: (error: unknown) => string;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const value = useContext(AppContext);
  if (!value) throw new Error("useApp outside AppProvider");
  return value;
}

export function errorKey(error: unknown): MessageKey {
  if (isUiError(error)) {
    const key = `error.${error.kind}`;
    if (key in catalogues.en) return key as MessageKey;
  }
  return "error.generic";
}

export function AppProvider({
  backend,
  status,
  settings,
  refreshStatus,
  updateSettings,
  children,
}: Omit<AppContextValue, "toast" | "errorText"> & { children: ReactNode }) {
  const { t } = useI18n();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const toast = useCallback((text: string, tone: Toast["tone"] = "info") => {
    const id = next.current++;
    setToasts((list) => [...list.slice(-2), { id, text, tone }]);
    window.setTimeout(() => setToasts((list) => list.filter((x) => x.id !== id)), 3600);
  }, []);

  const errorText = useCallback((error: unknown) => t(errorKey(error)), [t]);

  return (
    <AppContext.Provider
      value={{ backend, status, settings, refreshStatus, updateSettings, toast, errorText }}
    >
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className={`toast ${x.tone === "error" ? "error" : ""}`} role="status">
            <Icon name={x.tone === "error" ? "alert" : "check"} />
            <span>{x.text}</span>
          </div>
        ))}
      </div>
    </AppContext.Provider>
  );
}
