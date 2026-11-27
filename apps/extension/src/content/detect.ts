// Form detection: which visible fields are usernames, current passwords,
// new passwords and one-time codes. Heuristics only read the page; nothing
// is ever written into it here.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  newPasswords: HTMLInputElement[];
  otp: HTMLInputElement | null;
}

const USERNAME_HINT = /user|login|e-?mail|identifiant|identifier|account|compte|courriel|phone|tel/i;
const NEW_HINT = /new|nouveau|nouvelle|confirm|repeat|retype|again|register|signup|sign-up|create/i;
const CURRENT_HINT = /current|old|actuel|ancien|existing/i;
const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification.?code|security.?code|auth.?code|token|code.?de.?v[ée]rification/i;
const TEXT_TYPES = new Set(["text", "email", "tel", ""]);

/** Visible, enabled and editable: hidden or off-screen fields are never filled. */
export function isUsable(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly) return false;
  if (input.type === "hidden") return false;
  if (input.getAttribute("aria-hidden") === "true") return false;
  const rect = input.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return false;
  if (rect.right <= 0 || rect.bottom <= 0) return false;
  const view = input.ownerDocument.defaultView;
  if (!view) return false;
  for (let el: Element | null = input, depth = 0; el && depth < 12; el = el.parentElement, depth += 1) {
    const style = view.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    if (Number.parseFloat(style.opacity) < 0.1) return false;
  }
  return true;
}

function hints(input: HTMLInputElement): string {
  const label = input.labels?.[0]?.textContent ?? "";
  return [input.name, input.id, input.placeholder, input.getAttribute("aria-label") ?? "", label].join(" ");
}

function autocomplete(input: HTMLInputElement): string[] {
  return (input.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
}

export function isNewPassword(input: HTMLInputElement, siblings: HTMLInputElement[]): boolean {
  const ac = autocomplete(input);
  if (ac.includes("new-password")) return true;
  if (ac.includes("current-password")) return false;
  const text = hints(input);
  if (CURRENT_HINT.test(text)) return false;
  if (NEW_HINT.test(text)) return true;
  // Two or more password fields without hints: registration (password +
  // confirmation) or change form (current + new + confirmation).
  return siblings.length >= 2 && siblings.indexOf(input) > 0;
}

export function isOtp(input: HTMLInputElement): boolean {
  if (!TEXT_TYPES.has(input.type) && input.type !== "number") return false;
  if (autocomplete(input).includes("one-time-code")) return true;
  const max = input.maxLength;
  const short = max > 0 && max <= 10;
  return OTP_HINT.test(hints(input)) && (short || input.inputMode === "numeric" || input.type === "number");
}

function scope(input: HTMLInputElement): ParentNode {
  return input.form ?? input.ownerDocument;
}

function inputs(root: ParentNode): HTMLInputElement[] {
  return Array.from(root.querySelectorAll("input")).filter(isUsable);
}

function usernameFor(password: HTMLInputElement): HTMLInputElement | null {
  const candidates = inputs(scope(password)).filter(
    (i) => TEXT_TYPES.has(i.type) && !isOtp(i),
  );
  const before = candidates.filter(
    (i) => password.compareDocumentPosition(i) & Node.DOCUMENT_POSITION_PRECEDING,
  );
  const tagged = before.filter((i) => {
    const ac = autocomplete(i);
    return ac.includes("username") || ac.includes("email") || i.type === "email" || USERNAME_HINT.test(hints(i));
  });
  return tagged.at(-1) ?? before.at(-1) ?? null;
}

/** Names that clearly designate a login identifier (stricter than the
 * hints used next to a password field). */
const LONELY_USERNAME = /^(user(_?name)?|login|e-?mail|identifier|identifiant|account|session\[(username|email|login)\])$/i;

/** A username field alone (first step of a two-step login). */
function lonelyUsername(doc: Document): HTMLInputElement | null {
  return (
    inputs(doc).find((i) => {
      if (!TEXT_TYPES.has(i.type) || isOtp(i)) return false;
      const ac = autocomplete(i);
      return (
        ac.includes("username") ||
        (ac.includes("email") && i.type === "email") ||
        LONELY_USERNAME.test(i.name) ||
        LONELY_USERNAME.test(i.id)
      );
    }) ?? null
  );
}

export function detect(doc: Document): LoginFields {
  const passwords = inputs(doc).filter((i) => i.type === "password");
  const groups = new Map<ParentNode, HTMLInputElement[]>();
  for (const p of passwords) {
    const key = scope(p);
    groups.set(key, [...(groups.get(key) ?? []), p]);
  }
  let password: HTMLInputElement | null = null;
  const newPasswords: HTMLInputElement[] = [];
  for (const [, group] of groups) {
    for (const p of group) {
      if (isNewPassword(p, group)) newPasswords.push(p);
      else password ??= p;
    }
  }
  const anchor = password ?? newPasswords[0] ?? null;
  const username = anchor ? usernameFor(anchor) : lonelyUsername(doc);
  const otp = inputs(doc).find(isOtp) ?? null;
  return { username, password, newPasswords, otp };
}

export interface FormSummary {
  login: boolean;
  newPassword: boolean;
  otp: boolean;
}

export function summarize(fields: LoginFields): FormSummary {
  return {
    login: fields.password !== null || fields.username !== null,
    newPassword: fields.newPasswords.length > 0,
    otp: fields.otp !== null,
  };
}
