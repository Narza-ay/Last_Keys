import type { ItemView } from "../api/types";
import { draftFromView, emptyForm, formFromView, secretChange, toDraft } from "./drafts";

const login: ItemView = {
  id: "00000000-0000-4000-8000-000000000001",
  kind: "login",
  title: "Bank",
  favorite: true,
  folder: "Finance",
  tags: ["money", "bank"],
  hasNotes: true,
  customFields: [
    { name: "Customer", kind: "text", value: "C-1", hasValue: true },
    { name: "Answer", kind: "hidden", value: null, hasValue: true },
  ],
  history: [{ replacedAt: 1 }],
  createdAt: 1,
  updatedAt: 2,
  content: {
    type: "login",
    username: "alice",
    hasPassword: true,
    urls: ["https://bank.example/"],
    hasTotp: true,
    backupCodes: 2,
  },
};

describe("secret changes", () => {
  it("only an explicit removal deletes a stored secret", () => {
    expect(secretChange({ mode: "keep", value: "", present: true })).toEqual({ op: "keep" });
    expect(secretChange({ mode: "clear", value: "", present: true })).toEqual({ op: "clear" });
    expect(secretChange({ mode: "set", value: "", present: true })).toEqual({ op: "keep" });
    expect(secretChange({ mode: "set", value: "new", present: true })).toEqual({ op: "set", value: "new" });
    expect(secretChange({ mode: "set", value: "", present: false })).toEqual({ op: "keep" });
  });
});

describe("drafts from views", () => {
  it("keep every secret and every non-secret field unchanged", () => {
    const draft = draftFromView(login);
    expect(draft).toEqual({
      title: "Bank",
      favorite: true,
      folder: "Finance",
      tags: ["money", "bank"],
      notes: { op: "keep" },
      customFields: [
        { name: "Customer", kind: "text", value: { op: "set", value: "C-1" }, source: 0 },
        { name: "Answer", kind: "hidden", value: { op: "keep" }, source: 1 },
      ],
      content: {
        type: "login",
        username: "alice",
        password: { op: "keep" },
        urls: ["https://bank.example/"],
        totp: { op: "keep" },
        backupCodes: { op: "keep" },
      },
    });
    // No secret value can appear: the view has none.
    expect(JSON.stringify(draft)).not.toMatch(/s3cret/);
  });

  it("express user edits", () => {
    const form = formFromView(login);
    form.password = { ...form.password, mode: "set", value: "new-password" };
    form.totp = { ...form.totp, mode: "clear" };
    form.backupCodes = { mode: "set", text: " a1 \n\n b2 ", count: 2 };
    form.tags = " x, , y ";
    form.urls = ["https://bank.example/", "  "];
    form.folder = "  ";
    const draft = toDraft(form);
    expect(draft.tags).toEqual(["x", "y"]);
    expect(draft.folder).toBeNull();
    expect(draft.content).toMatchObject({
      password: { op: "set", value: "new-password" },
      totp: { op: "clear" },
      backupCodes: { op: "set", values: ["a1", "b2"] },
      urls: ["https://bank.example/"],
    });
  });

  it("build cards and identities", () => {
    const card = emptyForm("payment_card");
    card.title = "Visa";
    card.cardNumber = { mode: "set", value: "4111 1111 1111 1111", present: false };
    card.expiryMonth = "09";
    card.expiryYear = "2030";
    card.address.city = " Lyon ";
    expect(toDraft(card).content).toEqual({
      type: "payment_card",
      cardholderName: null,
      number: { op: "set", value: "4111 1111 1111 1111" },
      expiryMonth: 9,
      expiryYear: 2030,
      securityCode: { op: "keep" },
      pin: { op: "keep" },
      billingAddress: { line1: null, line2: null, city: "Lyon", postalCode: null, region: null, country: null },
    });
    const identity = formFromView({
      ...login,
      kind: "identity",
      content: {
        type: "identity",
        honorific: null,
        firstName: "Alice",
        middleName: null,
        lastName: "Martin",
        birthDate: null,
        email: null,
        phone: null,
        company: null,
        address: null,
        documents: [{ kind: "passport", issuingCountry: "FR", expiryDate: null, hasNumber: true }],
      },
    });
    const draft = toDraft(identity);
    expect(draft.content).toMatchObject({
      type: "identity",
      firstName: "Alice",
      address: null,
      documents: [{ kind: "passport", number: { op: "keep" }, source: 0, issuingCountry: "FR", expiryDate: null }],
    });
  });

  it("drop custom fields without a label", () => {
    const form = emptyForm("secure_note");
    form.title = "N";
    form.customFields = [{ name: " ", kind: "text", value: { mode: "set", value: "x", present: false }, source: null }];
    expect(toDraft(form).customFields).toEqual([]);
  });
});
