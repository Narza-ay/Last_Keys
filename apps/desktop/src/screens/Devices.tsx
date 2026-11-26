// The account's devices, verified with the account key; revocation.

import { useEffect, useState } from "react";
import type { DeviceView, Platform } from "../api/types";
import { Button, EmptyState, Notice } from "../components/controls";
import { Dialog } from "../components/Dialog";
import { Icon, type IconName } from "../components/Icon";
import { useI18n, type MessageKey } from "../i18n";
import { useApp } from "../state/app";
import type { SyncControl } from "./Shell";

const PLATFORM: Record<Platform, { icon: IconName; label: MessageKey }> = {
  windows: { icon: "laptop", label: "platform.windows" },
  mac_os: { icon: "laptop", label: "platform.mac_os" },
  linux: { icon: "laptop", label: "platform.linux" },
  android: { icon: "phone", label: "platform.android" },
  ios: { icon: "phone", label: "platform.ios" },
  web: { icon: "globe", label: "platform.web" },
  browser_extension: { icon: "globe", label: "platform.browser_extension" },
  cli: { icon: "terminal", label: "platform.cli" },
};

export function Devices({ sync, onOpenSettings }: { sync: SyncControl; onOpenSettings: () => void }) {
  const { t, date, dateTime } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [devices, setDevices] = useState<DeviceView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<DeviceView | null>(null);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const registered = sync.info?.remote != null;

  useEffect(() => {
    if (!registered) return;
    let cancelled = false;
    backend
      .devices()
      .then((list) => {
        if (cancelled) return;
        setDevices(list);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorText(err));
      });
    return () => {
      cancelled = true;
    };
  }, [registered, backend, errorText, reload]);

  if (sync.info && !registered) {
    return (
      <div className="page">
        <EmptyState
          icon="devices"
          title={t("devices.localTitle")}
          text={t("devices.localText")}
          action={
            <Button variant="primary" icon="cloud" onClick={onOpenSettings}>
              {t("devices.setUpSync")}
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-header">
          <h1>{t("devices.title")}</h1>
          <p>{t("devices.subtitle")}</p>
        </header>
        {error ? (
          <Notice tone="danger" icon="alert">
            {error}
          </Notice>
        ) : null}
        {devices ? (
          <div className="card">
            {devices.map((d) => {
              const platform = PLATFORM[d.platform];
              return (
                <div key={d.id} className={`device ${d.status === "revoked" ? "revoked" : ""}`}>
                  <div className="device-icon">
                    <Icon name={platform.icon} />
                  </div>
                  <div className="device-body">
                    <div className="device-name">
                      <span>{d.name}</span>
                      {d.status === "this_device" ? (
                        <span className="badge badge-accent">{t("devices.thisDevice")}</span>
                      ) : d.status === "revoked" ? (
                        <span className="badge badge-danger">{t("devices.revoked")}</span>
                      ) : (
                        <span className="badge badge-success">{t("devices.active")}</span>
                      )}
                    </div>
                    <div className="device-meta">
                      {t(platform.label)} · {t("devices.enrolled", { date: date(d.enrolledAt) })} ·{" "}
                      {d.lastSeen ? t("devices.lastSeen", { date: dateTime(d.lastSeen) }) : t("devices.neverSeen")}
                    </div>
                  </div>
                  {d.status === "active" ? (
                    <Button variant="danger-ghost" size="sm" onClick={() => setRevoking(d)}>
                      {t("devices.revoke")}
                    </Button>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : !error ? (
          <div className="empty">
            <span className="spinner" />
          </div>
        ) : null}
        <Notice icon="info">{t("devices.note")}</Notice>
      </div>
      {revoking ? (
        <Dialog
          title={t("devices.revokeTitle", { name: revoking.name })}
          icon="alert"
          danger
          onClose={() => setRevoking(null)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setRevoking(null)}>
                {t("action.cancel")}
              </Button>
              <Button
                variant="danger"
                busy={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await backend.revokeDevice(revoking.id);
                    toast(t("devices.revokedToast", { name: revoking.name }));
                    setRevoking(null);
                    setReload((n) => n + 1);
                  } catch (err) {
                    toast(errorText(err), "error");
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t("devices.revoke")}
              </Button>
            </>
          }
        >
          <p className="muted">{t("devices.revokeText")}</p>
          <Notice tone="warning" icon="alert">
            {t("devices.revokeWarning")}
          </Notice>
        </Dialog>
      ) : null}
    </div>
  );
}
