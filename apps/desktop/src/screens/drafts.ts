// Pure conversions between item views, editor form state and edit drafts.
// Secrets are never loaded into the editor: an existing secret is "kept"
// unless the user replaces or removes it.

import type {
  AddressView,
  ContentDraft,
  DocumentKind,
  FieldKind,
  ItemDraft,
  ItemKind,
  ItemView,
  ListChange,
  SecretChange,
} from "../api/types";

export interface SecretInput {
  /** keep: unchanged existing value; set: new value typed; clear: remove. */
  mode: "keep" | "set" | "clear";
  value: string;
  /** A value exists in the stored item. */
  present: boolean;
}

export interface AddressForm {
  line1: string;
  line2: string;
  city: string;
  postalCode: string;
  region: string;
  country: string;
}

export interface CustomFieldForm {
  name: string;
  kind: FieldKind;
  value: SecretInput;
  source: number | null;
}

export interface DocumentForm {
  kind: DocumentKind;
  number: SecretInput;
  source: number | null;
  issuingCountry: string;
  expiryDate: string;
}

export interface FormState {
  kind: ItemKind;
  title: string;
  favorite: boolean;
  folder: string;
  tags: string;
  notes: SecretInput;
  customFields: CustomFieldForm[];
  username: string;
  password: SecretInput;
  urls: string[];
  totp: SecretInput;
  backupCodes: { mode: "keep" | "set" | "clear"; text: string; count: number };
  cardholderName: string;
  cardNumber: SecretInput;
  expiryMonth: string;
  expiryYear: string;
  securityCode: SecretInput;
  pin: SecretInput;
  address: AddressForm;
  honorific: string;
  firstName: string;
  middleName: string;
  lastName: string;
  birthDate: string;
  email: string;
  phone: string;
  company: string;
  documents: DocumentForm[];
}

export const newSecret = (): SecretInput => ({ mode: "set", value: "", present: false });
export const keptSecret = (present: boolean): SecretInput =>
  present ? { mode: "keep", value: "", present } : newSecret();

const emptyAddress = (): AddressForm => ({
  line1: "",
  line2: "",
  city: "",
  postalCode: "",
  region: "",
  country: "",
});

function addressForm(a: AddressView | null): AddressForm {
  return {
    line1: a?.line1 ?? "",
    line2: a?.line2 ?? "",
    city: a?.city ?? "",
    postalCode: a?.postalCode ?? "",
    region: a?.region ?? "",
    country: a?.country ?? "",
  };
}

export function emptyForm(kind: ItemKind): FormState {
  return {
    kind,
    title: "",
    favorite: false,
    folder: "",
    tags: "",
    notes: newSecret(),
    customFields: [],
    username: "",
    password: newSecret(),
    urls: [""],
    totp: newSecret(),
    backupCodes: { mode: "set", text: "", count: 0 },
    cardholderName: "",
    cardNumber: newSecret(),
    expiryMonth: "",
    expiryYear: "",
    securityCode: newSecret(),
    pin: newSecret(),
    address: emptyAddress(),
    honorific: "",
    firstName: "",
    middleName: "",
    lastName: "",
    birthDate: "",
    email: "",
    phone: "",
    company: "",
    documents: [],
  };
}

/** Editor state for an existing item (secrets kept, not loaded). */
export function formFromView(view: ItemView): FormState {
  const form = emptyForm(view.kind);
  form.title = view.title;
  form.favorite = view.favorite;
  form.folder = view.folder ?? "";
  form.tags = view.tags.join(", ");
  form.notes = keptSecret(view.hasNotes);
  form.customFields = view.customFields.map((f, index) => ({
    name: f.name,
    kind: f.kind,
    // Visible fields are edited directly; hidden ones are kept unless changed.
    value:
      f.kind === "hidden"
        ? keptSecret(f.hasValue)
        : { mode: "set", value: f.value ?? "", present: f.hasValue },
    source: index,
  }));
  const c = view.content;
  if (c.type === "login") {
    form.username = c.username ?? "";
    form.password = keptSecret(c.hasPassword);
    form.urls = c.urls.length ? [...c.urls] : [""];
    form.totp = keptSecret(c.hasTotp);
    form.backupCodes = c.backupCodes
      ? { mode: "keep", text: "", count: c.backupCodes }
      : { mode: "set", text: "", count: 0 };
  } else if (c.type === "payment_card") {
    form.cardholderName = c.cardholderName ?? "";
    form.cardNumber = keptSecret(c.hasNumber);
    form.expiryMonth = c.expiryMonth ? String(c.expiryMonth) : "";
    form.expiryYear = c.expiryYear ? String(c.expiryYear) : "";
    form.securityCode = keptSecret(c.hasSecurityCode);
    form.pin = keptSecret(c.hasPin);
    form.address = addressForm(c.billingAddress);
  } else if (c.type === "identity") {
    form.honorific = c.honorific ?? "";
    form.firstName = c.firstName ?? "";
    form.middleName = c.middleName ?? "";
    form.lastName = c.lastName ?? "";
    form.birthDate = c.birthDate ?? "";
    form.email = c.email ?? "";
    form.phone = c.phone ?? "";
    form.company = c.company ?? "";
    form.address = addressForm(c.address);
    form.documents = c.documents.map((d, index) => ({
      kind: d.kind,
      number: keptSecret(d.hasNumber),
      source: index,
      issuingCountry: d.issuingCountry ?? "",
      expiryDate: d.expiryDate ?? "",
    }));
  }
  return form;
}

/** Only an explicit "remove" deletes a stored secret; an empty new value
 * keeps it. */
export function secretChange(s: SecretInput): SecretChange {
  if (s.mode === "clear") return { op: "clear" };
  if (s.mode === "set" && s.value !== "") return { op: "set", value: s.value };
  return { op: "keep" };
}

const text = (s: string): string | null => (s.trim() === "" ? null : s.trim());

function addressView(a: AddressForm): AddressView | null {
  const view: AddressView = {
    line1: text(a.line1),
    line2: text(a.line2),
    city: text(a.city),
    postalCode: text(a.postalCode),
    region: text(a.region),
    country: text(a.country),
  };
  return Object.values(view).some((v) => v !== null) ? view : null;
}

function number(s: string): number | null {
  const n = Number.parseInt(s, 10);
  return Number.isFinite(n) ? n : null;
}

/** The edit request for a form. */
export function toDraft(form: FormState): ItemDraft {
  let content: ContentDraft;
  switch (form.kind) {
    case "login": {
      const backupCodes: ListChange =
        form.backupCodes.mode === "keep"
          ? { op: "keep" }
          : form.backupCodes.mode === "clear"
            ? { op: "clear" }
            : {
                op: "set",
                values: form.backupCodes.text
                  .split("\n")
                  .map((l) => l.trim())
                  .filter(Boolean),
              };
      content = {
        type: "login",
        username: text(form.username),
        password: secretChange(form.password),
        urls: form.urls.map((u) => u.trim()).filter(Boolean),
        totp: secretChange(form.totp),
        backupCodes,
      };
      break;
    }
    case "secure_note":
      content = { type: "secure_note" };
      break;
    case "payment_card":
      content = {
        type: "payment_card",
        cardholderName: text(form.cardholderName),
        number: secretChange(form.cardNumber),
        expiryMonth: number(form.expiryMonth),
        expiryYear: number(form.expiryYear),
        securityCode: secretChange(form.securityCode),
        pin: secretChange(form.pin),
        billingAddress: addressView(form.address),
      };
      break;
    case "identity":
      content = {
        type: "identity",
        honorific: text(form.honorific),
        firstName: text(form.firstName),
        middleName: text(form.middleName),
        lastName: text(form.lastName),
        birthDate: text(form.birthDate),
        email: text(form.email),
        phone: text(form.phone),
        company: text(form.company),
        address: addressView(form.address),
        documents: form.documents.map((d) => ({
          kind: d.kind,
          number: secretChange(d.number),
          source: d.source,
          issuingCountry: text(d.issuingCountry),
          expiryDate: text(d.expiryDate),
        })),
      };
      break;
  }
  return {
    title: form.title.trim(),
    favorite: form.favorite,
    folder: text(form.folder),
    tags: form.tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    notes: secretChange(form.notes),
    customFields: form.customFields
      .filter((f) => f.name.trim() !== "")
      .map((f) => ({
        name: f.name.trim(),
        kind: f.kind,
        value: f.kind === "hidden" ? secretChange(f.value) : { op: "set", value: f.value.value },
        source: f.source,
      })),
    content,
  };
}

/** A draft that changes nothing (used to toggle the favorite flag). */
export function draftFromView(view: ItemView): ItemDraft {
  return toDraft(formFromView(view));
}
