// Writing values into fields the way a user's typing would: through the
// native value setter (so that frameworks tracking the property notice)
// followed by input and change events.

import type { LoginFields } from "./detect";
import { isUsable } from "./detect";

const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;

export function setValue(input: HTMLInputElement, value: string): boolean {
  if (!isUsable(input)) return false;
  input.focus();
  if (valueSetter) valueSetter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

export interface Credentials {
  username: string | null;
  password: string | null;
  totp: string | null;
}

/** Fills the detected fields; returns how many were written. */
export function fillLogin(fields: LoginFields, credentials: Credentials): number {
  let filled = 0;
  if (credentials.username && fields.username && setValue(fields.username, credentials.username)) filled += 1;
  if (credentials.password && fields.password && setValue(fields.password, credentials.password)) filled += 1;
  // A login form without a current-password field: the only password field
  // may have been taken for a new one (unusual markup). Use it.
  if (credentials.password && !fields.password && fields.newPasswords.length === 1) {
    const only = fields.newPasswords[0];
    if (only && setValue(only, credentials.password)) filled += 1;
  }
  if (credentials.totp && fields.otp && setValue(fields.otp, credentials.totp)) filled += 1;
  return filled;
}

/** Fills every new-password field (new password and its confirmation). */
export function fillNewPassword(fields: LoginFields, password: string): number {
  return fields.newPasswords.filter((input) => setValue(input, password)).length;
}
