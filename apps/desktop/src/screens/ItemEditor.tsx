// Create or edit an item. Stored secrets are never loaded: they show as
// "unchanged" until the user replaces or removes them.

import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import type { DocumentKind, FieldKind, ItemKind } from "../api/types";
import {
  Button,
  Field,
  IconButton,
  Notice,
  PasswordField,
  Select,
  TextArea,
  TextField,
  Toggle,
} from "../components/controls";
import { Icon } from "../components/Icon";
import { kindLabel } from "../components/ItemAvatar";
import { useI18n } from "../i18n";
import { useApp } from "../state/app";
import {
  emptyForm,
  formFromView,
  newSecret,
  toDraft,
  type AddressForm,
  type FormState,
  type SecretInput,
} from "./drafts";

const DEFAULT_PASSWORD = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

function SecretEditor({
  label,
  secret,
  onChange,
  multiline = false,
  generate = false,
  mono = true,
}: {
  label: string;
  secret: SecretInput;
  onChange: (s: SecretInput) => void;
  multiline?: boolean;
  generate?: boolean;
  mono?: boolean;
}) {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const id = useId();

  if (secret.mode === "keep" || secret.mode === "clear") {
    return (
      <Field label={label} htmlFor={id}>
        <div className="secret-unchanged" id={id}>
          <Icon name={secret.mode === "keep" ? "lock" : "trash"} width={15} height={15} />
          <span>{secret.mode === "keep" ? t("editor.unchanged") : t("editor.willRemove")}</span>
          {secret.mode === "keep" ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => onChange({ ...secret, mode: "set", value: "" })}>
                {t("action.change")}
              </Button>
              <Button size="sm" variant="danger-ghost" onClick={() => onChange({ ...secret, mode: "clear" })}>
                {t("action.remove")}
              </Button>
            </>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => onChange({ ...secret, mode: "keep" })}>
              {t("action.undo")}
            </Button>
          )}
        </div>
      </Field>
    );
  }

  const fill = async () => {
    try {
      const generated = await backend.generatePassword(DEFAULT_PASSWORD);
      onChange({ ...secret, value: generated.value });
    } catch (err) {
      toast(errorText(err), "error");
    }
  };
  const cancel =
    secret.present ? (
      <IconButton icon="close" label={t("action.cancelChange")} onClick={() => onChange({ ...secret, mode: "keep", value: "" })} />
    ) : null;

  if (multiline) {
    return (
      <div className="row-list-item">
        <TextArea
          label={label}
          value={secret.value}
          onChange={(e) => onChange({ ...secret, value: e.target.value })}
          rows={6}
        />
        {cancel}
      </div>
    );
  }
  return (
    <PasswordField
      label={label}
      value={secret.value}
      onChange={(e) => onChange({ ...secret, value: e.target.value })}
      className={mono ? "mono" : undefined}
      extraActions={
        <>
          {generate ? <IconButton icon="dice" label={t("action.generate")} onClick={() => void fill()} /> : null}
          {cancel}
        </>
      }
    />
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="editor-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function AddressFields({ value, onChange }: { value: AddressForm; onChange: (a: AddressForm) => void }) {
  const { t } = useI18n();
  const set = (key: keyof AddressForm) => (e: { target: { value: string } }) =>
    onChange({ ...value, [key]: e.target.value });
  return (
    <>
      <TextField label={t("field.addressLine1")} value={value.line1} onChange={set("line1")} />
      <TextField label={t("field.addressLine2")} value={value.line2} onChange={set("line2")} />
      <div className="grid-3">
        <TextField label={t("field.postalCode")} value={value.postalCode} onChange={set("postalCode")} />
        <TextField label={t("field.city")} value={value.city} onChange={set("city")} />
        <TextField label={t("field.country")} value={value.country} onChange={set("country")} maxLength={2} hint={t("field.countryHint")} />
      </div>
    </>
  );
}

export function ItemEditor({
  itemId,
  kind,
  onCancel,
  onSaved,
}: {
  itemId?: string;
  kind?: ItemKind;
  onCancel: () => void;
  onSaved: (id: string) => void;
}) {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [form, setForm] = useState<FormState | null>(kind ? emptyForm(kind) : null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!itemId) return;
    backend
      .getItem(itemId)
      .then((view) => setForm(formFromView(view)))
      .catch((err: unknown) => toast(errorText(err), "error"));
  }, [backend, itemId, errorText, toast]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector(".dialog")) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  if (!form) return null;
  const update = (patch: Partial<FormState>) => setForm({ ...form, ...patch });
  const isNew = !itemId;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const draft = toDraft(form);
      let id = itemId;
      if (id) await backend.updateItem(id, draft);
      else id = await backend.createItem(draft);
      toast(isNew ? t("editor.created") : t("editor.saved"));
      onSaved(id);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  const fieldKinds: { value: FieldKind; label: string }[] = [
    { value: "text", label: t("fieldKind.text") },
    { value: "hidden", label: t("fieldKind.hidden") },
    { value: "url", label: t("fieldKind.url") },
    { value: "email", label: t("fieldKind.email") },
  ];
  const documentKinds: { value: DocumentKind; label: string }[] = [
    { value: "passport", label: t("document.passport") },
    { value: "national_id", label: t("document.national_id") },
    { value: "driver_license", label: t("document.driver_license") },
    { value: "social_security", label: t("document.social_security") },
    { value: "other", label: t("document.other") },
  ];

  return (
    <form className="editor" onSubmit={submit}>
      <div className="editor-header">
        <h2>{isNew ? t("editor.newTitle", { kind: t(kindLabel[form.kind]) }) : t("editor.editTitle")}</h2>
        <div className="detail-actions">
          <Button variant="ghost" onClick={onCancel}>
            {t("action.cancel")}
          </Button>
          <Button type="submit" variant="primary" icon="check" busy={busy} disabled={!form.title.trim()}>
            {t("action.save")}
          </Button>
        </div>
      </div>
      {error ? (
        <Notice tone="danger" icon="alert">
          {error}
        </Notice>
      ) : null}

      <Section title={t("editor.general")}>
        <TextField
          label={t("field.title")}
          value={form.title}
          onChange={(e) => update({ title: e.target.value })}
          autoFocus
          maxLength={512}
        />
        <div className="grid-2">
          <TextField label={t("field.folder")} value={form.folder} onChange={(e) => update({ folder: e.target.value })} />
          <TextField
            label={t("field.tags")}
            value={form.tags}
            onChange={(e) => update({ tags: e.target.value })}
            hint={t("field.tagsHint")}
          />
        </div>
        <Toggle label={t("field.favorite")} checked={form.favorite} onChange={(favorite) => update({ favorite })} />
      </Section>

      {form.kind === "login" ? (
        <Section title={t("editor.credentials")}>
          <TextField label={t("field.username")} value={form.username} onChange={(e) => update({ username: e.target.value })} />
          <SecretEditor label={t("field.password")} secret={form.password} onChange={(password) => update({ password })} generate />
          <div className="row-list">
            {form.urls.map((url, index) => (
              <div className="row-list-item" key={index}>
                <TextField
                  label={index === 0 ? t("field.website") : t("field.websiteN", { n: index + 1 })}
                  value={url}
                  icon="link"
                  inputMode="url"
                  onChange={(e) => update({ urls: form.urls.map((u, i) => (i === index ? e.target.value : u)) })}
                  actions={
                    form.urls.length > 1 ? (
                      <IconButton
                        icon="close"
                        label={t("action.remove")}
                        onClick={() => update({ urls: form.urls.filter((_, i) => i !== index) })}
                      />
                    ) : undefined
                  }
                />
              </div>
            ))}
            <div>
              <Button size="sm" variant="ghost" icon="plus" onClick={() => update({ urls: [...form.urls, ""] })}>
                {t("editor.addWebsite")}
              </Button>
            </div>
          </div>
          <SecretEditor label={t("field.totpSecret")} secret={form.totp} onChange={(totp) => update({ totp })} />
          {form.backupCodes.mode === "keep" ? (
            <Field label={t("field.backupCodes")} htmlFor="backup-codes-kept">
              <div className="secret-unchanged" id="backup-codes-kept">
                <Icon name="lock" width={15} height={15} />
                <span>{t("editor.backupCodesKept", { count: form.backupCodes.count })}</span>
                <Button size="sm" variant="ghost" onClick={() => update({ backupCodes: { ...form.backupCodes, mode: "set", text: "" } })}>
                  {t("action.replace")}
                </Button>
                <Button size="sm" variant="danger-ghost" onClick={() => update({ backupCodes: { ...form.backupCodes, mode: "clear" } })}>
                  {t("action.remove")}
                </Button>
              </div>
            </Field>
          ) : form.backupCodes.mode === "clear" ? (
            <Field label={t("field.backupCodes")} htmlFor="backup-codes-cleared">
              <div className="secret-unchanged" id="backup-codes-cleared">
                <Icon name="trash" width={15} height={15} />
                <span>{t("editor.willRemove")}</span>
                <Button size="sm" variant="ghost" onClick={() => update({ backupCodes: { ...form.backupCodes, mode: "keep" } })}>
                  {t("action.undo")}
                </Button>
              </div>
            </Field>
          ) : (
            <TextArea
              label={t("field.backupCodes")}
              hint={t("field.backupCodesHint")}
              value={form.backupCodes.text}
              onChange={(e) => update({ backupCodes: { ...form.backupCodes, text: e.target.value } })}
              rows={3}
              className="mono"
            />
          )}
        </Section>
      ) : null}

      {form.kind === "payment_card" ? (
        <Section title={t("editor.card")}>
          <TextField
            label={t("field.cardholder")}
            value={form.cardholderName}
            onChange={(e) => update({ cardholderName: e.target.value })}
          />
          <SecretEditor label={t("field.cardNumber")} secret={form.cardNumber} onChange={(cardNumber) => update({ cardNumber })} />
          <div className="grid-3">
            <TextField
              label={t("field.expiryMonth")}
              value={form.expiryMonth}
              onChange={(e) => update({ expiryMonth: e.target.value.replace(/\D/g, "").slice(0, 2) })}
              inputMode="numeric"
              placeholder={t("field.monthPlaceholder")}
            />
            <TextField
              label={t("field.expiryYear")}
              value={form.expiryYear}
              onChange={(e) => update({ expiryYear: e.target.value.replace(/\D/g, "").slice(0, 4) })}
              inputMode="numeric"
              placeholder={t("field.yearPlaceholder")}
            />
            <SecretEditor label={t("field.securityCode")} secret={form.securityCode} onChange={(securityCode) => update({ securityCode })} />
          </div>
          <SecretEditor label={t("field.pin")} secret={form.pin} onChange={(pin) => update({ pin })} />
          <h3>{t("field.billingAddress")}</h3>
          <AddressFields value={form.address} onChange={(address) => update({ address })} />
        </Section>
      ) : null}

      {form.kind === "identity" ? (
        <>
          <Section title={t("editor.person")}>
            <div className="grid-3">
              <TextField label={t("field.honorific")} value={form.honorific} onChange={(e) => update({ honorific: e.target.value })} />
              <TextField label={t("field.firstName")} value={form.firstName} onChange={(e) => update({ firstName: e.target.value })} />
              <TextField label={t("field.lastName")} value={form.lastName} onChange={(e) => update({ lastName: e.target.value })} />
            </div>
            <div className="grid-2">
              <TextField label={t("field.middleName")} value={form.middleName} onChange={(e) => update({ middleName: e.target.value })} />
              <TextField
                label={t("field.birthDate")}
                value={form.birthDate}
                onChange={(e) => update({ birthDate: e.target.value })}
                type="date"
              />
            </div>
            <div className="grid-2">
              <TextField label={t("field.email")} type="email" value={form.email} onChange={(e) => update({ email: e.target.value })} />
              <TextField label={t("field.phone")} type="tel" value={form.phone} onChange={(e) => update({ phone: e.target.value })} />
            </div>
            <TextField label={t("field.company")} value={form.company} onChange={(e) => update({ company: e.target.value })} />
            <h3>{t("field.address")}</h3>
            <AddressFields value={form.address} onChange={(address) => update({ address })} />
          </Section>
          <Section title={t("detail.documents")}>
            {form.documents.map((doc, index) => (
              <div className="editor-section" key={index}>
                <div className="grid-2">
                  <Select
                    label={t("field.documentType")}
                    value={doc.kind}
                    options={documentKinds}
                    onChange={(e) =>
                      update({
                        documents: form.documents.map((d, i) =>
                          i === index ? { ...d, kind: e.target.value as DocumentKind } : d,
                        ),
                      })
                    }
                  />
                  <SecretEditor
                    label={t("field.documentNumber")}
                    secret={doc.number}
                    onChange={(number) =>
                      update({ documents: form.documents.map((d, i) => (i === index ? { ...d, number } : d)) })
                    }
                  />
                </div>
                <div className="grid-2">
                  <TextField
                    label={t("field.issuingCountry")}
                    value={doc.issuingCountry}
                    maxLength={2}
                    hint={t("field.countryHint")}
                    onChange={(e) =>
                      update({
                        documents: form.documents.map((d, i) => (i === index ? { ...d, issuingCountry: e.target.value } : d)),
                      })
                    }
                  />
                  <TextField
                    label={t("field.expiryDate")}
                    type="date"
                    value={doc.expiryDate}
                    onChange={(e) =>
                      update({
                        documents: form.documents.map((d, i) => (i === index ? { ...d, expiryDate: e.target.value } : d)),
                      })
                    }
                  />
                </div>
                <div>
                  <Button
                    size="sm"
                    variant="danger-ghost"
                    icon="trash"
                    onClick={() => update({ documents: form.documents.filter((_, i) => i !== index) })}
                  >
                    {t("editor.removeDocument")}
                  </Button>
                </div>
              </div>
            ))}
            <div>
              <Button
                size="sm"
                variant="ghost"
                icon="plus"
                onClick={() =>
                  update({
                    documents: [
                      ...form.documents,
                      { kind: "passport", number: newSecret(), source: null, issuingCountry: "", expiryDate: "" },
                    ],
                  })
                }
              >
                {t("editor.addDocument")}
              </Button>
            </div>
          </Section>
        </>
      ) : null}

      <Section title={form.kind === "secure_note" ? t("field.note") : t("field.notes")}>
        <SecretEditor
          label={form.kind === "secure_note" ? t("field.note") : t("field.notes")}
          secret={form.notes}
          onChange={(notes) => update({ notes })}
          multiline
          mono={false}
        />
      </Section>

      <Section title={t("detail.customFields")}>
        {form.customFields.map((f, index) => (
          <div className="row-list-item" key={index}>
            <TextField
              label={t("field.fieldName")}
              value={f.name}
              onChange={(e) =>
                update({ customFields: form.customFields.map((x, i) => (i === index ? { ...x, name: e.target.value } : x)) })
              }
            />
            <Select
              label={t("field.fieldKind")}
              value={f.kind}
              options={fieldKinds}
              onChange={(e) => {
                const kind = e.target.value as FieldKind;
                update({
                  customFields: form.customFields.map((x, i) =>
                    i === index
                      ? {
                          ...x,
                          kind,
                          // Switching type means typing the value again.
                          value: kind === "hidden" || x.kind === "hidden" ? newSecret() : x.value,
                          source: kind === "hidden" || x.kind === "hidden" ? null : x.source,
                        }
                      : x,
                  ),
                });
              }}
            />
            {f.kind === "hidden" ? (
              <SecretEditor
                label={t("field.fieldValue")}
                secret={f.value}
                onChange={(value) =>
                  update({ customFields: form.customFields.map((x, i) => (i === index ? { ...x, value } : x)) })
                }
              />
            ) : (
              <TextField
                label={t("field.fieldValue")}
                value={f.value.value}
                onChange={(e) =>
                  update({
                    customFields: form.customFields.map((x, i) =>
                      i === index ? { ...x, value: { ...x.value, mode: "set", value: e.target.value } } : x,
                    ),
                  })
                }
              />
            )}
            <IconButton
              icon="trash"
              label={t("action.remove")}
              onClick={() => update({ customFields: form.customFields.filter((_, i) => i !== index) })}
              style={{ marginTop: 26 }}
            />
          </div>
        ))}
        <div>
          <Button
            size="sm"
            variant="ghost"
            icon="plus"
            onClick={() =>
              update({ customFields: [...form.customFields, { name: "", kind: "text", value: newSecret(), source: null }] })
            }
          >
            {t("editor.addField")}
          </Button>
        </div>
      </Section>
    </form>
  );
}
