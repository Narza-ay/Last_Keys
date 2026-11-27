// Pairing approval (ADR-0011): shown over any screen when a browser
// extension asks to connect. The user compares the code with the one the
// extension's popup shows. Closing the dialog refuses.

import { useCallback, useEffect, useState } from "react";
import type { PairingRequestView } from "../api/types";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";
import { Button } from "./controls";
import { Dialog } from "./Dialog";

export function PairingPrompt() {
  const { t } = useI18n();
  const { backend, toast, errorText } = useApp();
  const [request, setRequest] = useState<PairingRequestView | null>(null);

  useEffect(() => {
    let disposed = false;
    const unlisten: (() => void)[] = [];
    const keep = (fn: () => void) => (disposed ? fn() : unlisten.push(fn));
    void backend.onPairingRequest((r) => setRequest(r)).then(keep);
    void backend
      .onPairingClosed((id) => setRequest((current) => (current?.id === id ? null : current)))
      .then(keep);
    // A request may have arrived before the window was ready.
    void backend
      .bridgeStatus()
      .then((s) => {
        if (!disposed && s.pending) setRequest(s.pending);
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      unlisten.forEach((fn) => fn());
    };
  }, [backend]);

  const decide = useCallback(
    async (approve: boolean) => {
      if (!request) return;
      const id = request.id;
      setRequest(null);
      try {
        const answered = await backend.pairingDecision(id, approve);
        if (answered && approve) toast(t("pairing.approved"));
      } catch (err) {
        toast(errorText(err), "error");
      }
    },
    [backend, request, t, toast, errorText],
  );

  if (!request) return null;
  const browser = request.browser === "firefox" ? "Firefox" : t("pairing.chromium");

  return (
    <Dialog
      title={t("pairing.title")}
      icon="link"
      onClose={() => void decide(false)}
      actions={
        <>
          <Button variant="ghost" onClick={() => void decide(false)}>
            {t("pairing.refuse")}
          </Button>
          <Button variant="primary" icon="check" onClick={() => void decide(true)}>
            {t("pairing.approve")}
          </Button>
        </>
      }
    >
      <p className="muted">{t("pairing.text", { name: request.clientName, browser })}</p>
      <p className="pairing-code mono selectable" aria-label={t("pairing.codeLabel")}>
        {request.code}
      </p>
      <p className="muted small">{t("pairing.extension", { id: request.extension })}</p>
      <p className="muted small">{t("pairing.warning")}</p>
    </Dialog>
  );
}
