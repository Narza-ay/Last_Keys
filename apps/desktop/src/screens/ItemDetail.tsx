// Read-only view of an item. Secret values are fetched only on an explicit
// reveal and hidden again after 30 s; copies go from Rust to the clipboard.

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { AddressView, Field, ItemView, TotpView } from "../api/types";
import { Button, IconButton } from "../components/controls";
import { Dialog } from "../components/Dialog";
import { ItemAvatar, kindLabel } from "../components/ItemAvatar";
import { useI18n, type MessageKey } from "../i18n";
import { useApp } from "../state/app";
import { draftFromView } from "./drafts";

const REVEAL_MS = 30_000;
const MASK = "••••••••••••";

function fieldKey(field: Field): string {
  return "index" in field ? `${field.field}:${field.index}` : field.field;
}

function useReveal(itemId: string) {
  const { backend, errorText, toast } = useApp();
  const [values, setValues] = useState<Record<string, string>>({});
  const timers = useRef<Record<string, number>>({});

  useEffect(() => {
    const current = timers.current;
    return () => Object.values(current).forEach((id) => window.clearTimeout(id));
  }, []);

  const hide = useCallback((key: string) => {
    setValues((v) => Object.fromEntries(Object.entries(v).filter(([k]) => k !== key)));
  }, []);

  const toggle = useCallback(
    async (field: Field) => {
      const key = fieldKey(field);
      if (key in values) {
        hide(key);
        return;
      }
      try {
        const value = await backend.revealField(itemId, field);
        setValues((v) => ({ ...v, [key]: value }));
        window.clearTimeout(timers.current[key]);
        timers.current[key] = window.setTimeout(() => hide(key), REVEAL_MS);
      } catch (err) {
        toast(errorText(err), "error");
      }
    },
    [backend, itemId, values, hide, errorText, toast],
  );

  return { values, toggle, get: (field: Field) => values[fieldKey(field)] };
}

function useCopy(itemId: string) {
  const { backend, errorText, toast } = useApp();
  const { t } = useI18n();
  return useCallback(
    async (field: Field) => {
      try {
        const r = await backend.copyField(itemId, field);
        toast(t("toast.copied", { seconds: r.clearsInSeconds }));
      } catch (err) {
        toast(errorText(err), "error");
      }
    },
    [backend, itemId, errorText, toast, t],
  );
}

function Row({
  label,
  value,
  secret = false,
  multiline = false,
  actions,
}: {
  label: string;
  value: ReactNode;
  secret?: boolean;
  multiline?: boolean;
  actions?: ReactNode;
}) {
  return (
    <div className="field-row">
      <div className="field-row-body">
        <div className="field-row-label">{label}</div>
        <div className={`field-row-value ${secret ? "secret" : ""} ${multiline ? "multiline" : ""}`}>
          {value}
        </div>
      </div>
      {actions ? <div className="field-row-actions">{actions}</div> : null}
    </div>
  );
}

function SecretRow({
  label,
  field,
  reveal,
  copy,
  masked = MASK,
  multiline = false,
}: {
  label: string;
  field: Field;
  reveal: ReturnType<typeof useReveal>;
  copy: (field: Field) => void;
  masked?: string;
  multiline?: boolean;
}) {
  const { t } = useI18n();
  const value = reveal.get(field);
  return (
    <Row
      label={label}
      value={value ?? masked}
      secret={value === undefined || !multiline}
      multiline={multiline && value !== undefined}
      actions={
        <>
          <IconButton
            icon={value === undefined ? "eye" : "eyeOff"}
            label={value === undefined ? t("action.reveal") : t("action.hide")}
            onClick={() => void reveal.toggle(field)}
          />
          <IconButton icon="copy" label={t("action.copy")} onClick={() => copy(field)} />
        </>
      }
    />
  );
}

function CopyRow({ label, value, field, copy }: { label: string; value: string; field: Field; copy: (f: Field) => void }) {
  const { t } = useI18n();
  return (
    <Row
      label={label}
      value={value}
      actions={<IconButton icon="copy" label={t("action.copy")} onClick={() => copy(field)} />}
    />
  );
}

function Totp({ itemId, copy }: { itemId: string; copy: (f: Field) => void }) {
  const { backend } = useApp();
  const { t } = useI18n();
  const [totp, setTotp] = useState<TotpView | null>(null);
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let left = 0;
    const fetchCode = async () => {
      try {
        const view = await backend.totp(itemId);
        if (cancelled) return;
        setTotp(view);
        left = view.remaining;
        setRemaining(left);
      } catch {
        if (!cancelled) setTotp(null);
      }
    };
    void fetchCode();
    const id = window.setInterval(() => {
      left -= 1;
      if (left <= 0) void fetchCode();
      else setRemaining(left);
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [backend, itemId]);

  if (!totp) return <Row label={t("field.totp")} value="…" />;
  const radius = 8;
  const circumference = 2 * Math.PI * radius;
  const fraction = remaining / totp.period;
  const code = totp.code.length === 6 ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}` : totp.code;
  return (
    <Row
      label={t("field.totp")}
      value={
        <span className="totp-code" aria-label={t("detail.totpRemaining", { seconds: remaining })}>
          <span>{code}</span>
          <svg className={`totp-ring ${remaining <= 5 ? "ending" : ""}`} viewBox="0 0 22 22" aria-hidden="true">
            <circle className="track" cx="11" cy="11" r={radius} />
            <circle
              className="progress"
              cx="11"
              cy="11"
              r={radius}
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - fraction)}
            />
          </svg>
        </span>
      }
      actions={<IconButton icon="copy" label={t("action.copy")} onClick={() => copy({ field: "totpCode" })} />}
    />
  );
}

function formatAddress(a: AddressView | null): string | null {
  if (!a) return null;
  const cityLine = [a.postalCode, a.city].filter(Boolean).join(" ");
  const lines = [a.line1, a.line2, cityLine, a.region, a.country].filter((x) => x && x.trim());
  return lines.length ? lines.join("\n") : null;
}

const DOCUMENT_LABEL: Record<string, MessageKey> = {
  passport: "document.passport",
  national_id: "document.national_id",
  driver_license: "document.driver_license",
  social_security: "document.social_security",
  other: "document.other",
};

export function ItemDetail({
  itemId,
  version,
  onEdit,
  onChanged,
  onDeleted,
}: {
  itemId: string;
  version: number;
  onEdit: () => void;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const { t, date, dateTime } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [view, setView] = useState<ItemView | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const reveal = useReveal(itemId);
  const copyField = useCopy(itemId);
  const copy = (field: Field) => void copyField(field);

  const load = useCallback(() => {
    backend
      .getItem(itemId)
      .then(setView)
      .catch((err: unknown) => toast(errorText(err), "error"));
  }, [backend, itemId, errorText, toast]);

  useEffect(load, [load, version]);

  if (!view) return null;
  const c = view.content;

  const toggleFavorite = async () => {
    try {
      await backend.updateItem(view.id, { ...draftFromView(view), favorite: !view.favorite });
      load();
      onChanged();
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  const historyAction = async (action: "restore" | "delete", index: number) => {
    try {
      if (action === "restore") {
        await backend.restorePassword(view.id, index);
        toast(t("detail.restored"));
      } else {
        await backend.deleteHistoryEntry(view.id, index);
      }
      load();
      onChanged();
    } catch (err) {
      toast(errorText(err), "error");
    }
  };

  const rows: ReactNode[] = [];
  if (c.type === "login") {
    if (c.username) rows.push(<CopyRow key="user" label={t("field.username")} value={c.username} field={{ field: "username" }} copy={copy} />);
    if (c.hasPassword) rows.push(<SecretRow key="pw" label={t("field.password")} field={{ field: "password" }} reveal={reveal} copy={copy} />);
    if (c.hasTotp) rows.push(<Totp key="totp" itemId={view.id} copy={copy} />);
    c.urls.forEach((url, index) =>
      rows.push(<CopyRow key={`url${index}`} label={t("field.website")} value={url} field={{ field: "url", index }} copy={copy} />),
    );
    for (let index = 0; index < c.backupCodes; index++) {
      rows.push(
        <SecretRow
          key={`bc${index}`}
          label={t("field.backupCodeN", { n: index + 1 })}
          field={{ field: "backupCode", index }}
          reveal={reveal}
          copy={copy}
        />,
      );
    }
  } else if (c.type === "payment_card") {
    if (c.cardholderName) rows.push(<Row key="holder" label={t("field.cardholder")} value={c.cardholderName} />);
    if (c.hasNumber)
      rows.push(
        <SecretRow
          key="number"
          label={t("field.cardNumber")}
          field={{ field: "cardNumber" }}
          reveal={reveal}
          copy={copy}
          masked={c.numberLast4 ? `•••• •••• •••• ${c.numberLast4}` : MASK}
        />,
      );
    if (c.expiryMonth && c.expiryYear)
      rows.push(<Row key="exp" label={t("field.expiry")} value={`${String(c.expiryMonth).padStart(2, "0")} / ${c.expiryYear}`} />);
    if (c.hasSecurityCode)
      rows.push(<SecretRow key="cvc" label={t("field.securityCode")} field={{ field: "securityCode" }} reveal={reveal} copy={copy} masked="•••" />);
    if (c.hasPin) rows.push(<SecretRow key="pin" label={t("field.pin")} field={{ field: "pin" }} reveal={reveal} copy={copy} masked="••••" />);
    const address = formatAddress(c.billingAddress);
    if (address) rows.push(<Row key="addr" label={t("field.billingAddress")} value={address} multiline />);
  } else if (c.type === "identity") {
    const name = [c.honorific, c.firstName, c.middleName, c.lastName].filter(Boolean).join(" ");
    if (name) rows.push(<Row key="name" label={t("field.fullName")} value={name} />);
    if (c.email) rows.push(<Row key="email" label={t("field.email")} value={c.email} />);
    if (c.phone) rows.push(<Row key="phone" label={t("field.phone")} value={c.phone} />);
    if (c.company) rows.push(<Row key="company" label={t("field.company")} value={c.company} />);
    if (c.birthDate) rows.push(<Row key="birth" label={t("field.birthDate")} value={c.birthDate} />);
    const address = formatAddress(c.address);
    if (address) rows.push(<Row key="addr" label={t("field.address")} value={address} multiline />);
  }

  const documents =
    c.type === "identity"
      ? c.documents.map((d, index) => (
          <div className="fields" key={`doc${index}`}>
            <Row
              label={t("field.documentType")}
              value={t(DOCUMENT_LABEL[d.kind] ?? "document.other")}
            />
            {d.hasNumber ? (
              <SecretRow label={t("field.documentNumber")} field={{ field: "documentNumber", index }} reveal={reveal} copy={copy} />
            ) : null}
            {d.issuingCountry ? <Row label={t("field.issuingCountry")} value={d.issuingCountry} /> : null}
            {d.expiryDate ? <Row label={t("field.expiryDate")} value={d.expiryDate} /> : null}
          </div>
        ))
      : [];

  const custom = view.customFields.map((f, index) =>
    f.kind === "hidden" ? (
      <SecretRow key={`cf${index}`} label={f.name} field={{ field: "customField", index }} reveal={reveal} copy={copy} />
    ) : (
      <CopyRow key={`cf${index}`} label={f.name} value={f.value ?? ""} field={{ field: "customField", index }} copy={copy} />
    ),
  );

  return (
    <article className="detail">
      <header className="detail-header">
        <ItemAvatar kind={view.kind} title={view.title} large />
        <div className="detail-heading">
          <h2 className="selectable">{view.title}</h2>
          <div className="detail-meta">
            <span className="badge">{t(kindLabel[view.kind])}</span>
            {view.folder ? <span className="badge badge-accent">{view.folder}</span> : null}
            {view.tags.map((tag) => (
              <span className="tag" key={tag}>
                {tag}
              </span>
            ))}
          </div>
        </div>
        <div className="detail-actions">
          <IconButton
            icon="star"
            filled={view.favorite}
            active={view.favorite}
            label={view.favorite ? t("action.unfavorite") : t("action.favorite")}
            onClick={() => void toggleFavorite()}
          />
          <IconButton icon="edit" label={t("action.edit")} onClick={onEdit} />
          <IconButton icon="trash" label={t("action.delete")} onClick={() => setConfirmDelete(true)} />
        </div>
      </header>

      {rows.length ? <div className="fields">{rows}</div> : null}
      {documents.length ? (
        <>
          <div className="fields-title">{t("detail.documents")}</div>
          {documents}
        </>
      ) : null}
      {view.hasNotes ? (
        <>
          <div className="fields-title">{c.type === "secure_note" ? t("field.note") : t("field.notes")}</div>
          <div className="fields">
            <SecretRow label={t("field.notes")} field={{ field: "notes" }} reveal={reveal} copy={copy} multiline />
          </div>
        </>
      ) : null}
      {custom.length ? (
        <>
          <div className="fields-title">{t("detail.customFields")}</div>
          <div className="fields">{custom}</div>
        </>
      ) : null}
      {view.history.length ? (
        <>
          <div className="fields-title">{t("detail.history")}</div>
          <div className="fields">
            {view.history.map((h, index) => {
              const field: Field = { field: "historyPassword", index };
              const value = reveal.get(field);
              return (
                <Row
                  key={`h${index}`}
                  label={t("detail.replacedOn", { date: dateTime(h.replacedAt) })}
                  value={value ?? MASK}
                  secret
                  actions={
                    <>
                      <IconButton
                        icon={value === undefined ? "eye" : "eyeOff"}
                        label={value === undefined ? t("action.reveal") : t("action.hide")}
                        onClick={() => void reveal.toggle(field)}
                      />
                      <IconButton icon="copy" label={t("action.copy")} onClick={() => copy(field)} />
                      <IconButton icon="restore" label={t("action.restore")} onClick={() => void historyAction("restore", index)} />
                      <IconButton icon="trash" label={t("action.delete")} onClick={() => void historyAction("delete", index)} />
                    </>
                  }
                />
              );
            })}
          </div>
        </>
      ) : null}
      <footer className="detail-footer">
        <span>{t("detail.created", { date: date(view.createdAt) })}</span>
        <span>{t("detail.modified", { date: dateTime(view.updatedAt) })}</span>
      </footer>

      {confirmDelete ? (
        <Dialog
          title={t("detail.deleteTitle")}
          icon="trash"
          danger
          onClose={() => setConfirmDelete(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
                {t("action.cancel")}
              </Button>
              <Button
                variant="danger"
                icon="trash"
                onClick={async () => {
                  try {
                    await backend.deleteItem(view.id);
                    setConfirmDelete(false);
                    toast(t("detail.deleted"));
                    onDeleted();
                  } catch (err) {
                    toast(errorText(err), "error");
                  }
                }}
              >
                {t("action.delete")}
              </Button>
            </>
          }
        >
          <p className="muted">{t("detail.deleteText", { title: view.title })}</p>
        </Dialog>
      ) : null}
    </article>
  );
}
