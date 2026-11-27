// Capture of submitted credentials: a form submission, a click on a submit
// button, or Enter in a password field. The values are read from the
// detected fields at that moment and reported to the background, which
// asks the user before saving anything.

import { detect, type LoginFields } from "./detect";

export interface Submission {
  username: string | null;
  password: string;
}

export function submissionFrom(fields: LoginFields): Submission | null {
  // A change or registration form: the new password is what to save.
  const fresh = fields.newPasswords.map((i) => i.value).find((v) => v.length > 0);
  const current = fields.password?.value ?? "";
  const password = fresh ?? (current.length > 0 ? current : null);
  if (!password) return null;
  const username = fields.username?.value.trim() ?? "";
  return { username: username.length > 0 ? username : null, password };
}

function isSubmitControl(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  const control = target.closest("button, input[type=submit], input[type=image], [role=button]");
  if (!control) return false;
  if (control instanceof HTMLButtonElement) return control.type === "submit";
  if (control instanceof HTMLInputElement) return true;
  // A clickable element near password fields (forms built without <form>).
  return /log ?in|sign ?in|connexion|se connecter|continue|continuer|submit|valider|register|s.inscrire|save|enregistrer/i.test(
    control.textContent ?? "",
  );
}

/** Watches a document; calls `report` at most once per distinct submission. */
export function watchSubmissions(doc: Document, report: (s: Submission) => void): () => void {
  let last = "";
  let lastAt = 0;
  const capture = () => {
    const submission = submissionFrom(detect(doc));
    if (!submission) return;
    const key = `${submission.username ?? ""}\u0000${submission.password}`;
    const now = Date.now();
    if (key === last && now - lastAt < 3000) return;
    last = key;
    lastAt = now;
    report(submission);
  };
  const onSubmit = () => capture();
  const onClick = (e: Event) => {
    if (isSubmitControl(e.target)) capture();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && e.target instanceof HTMLInputElement && (e.target.type === "password" || e.target.form)) {
      capture();
    }
  };
  doc.addEventListener("submit", onSubmit, true);
  doc.addEventListener("click", onClick, true);
  doc.addEventListener("keydown", onKey, true);
  return () => {
    doc.removeEventListener("submit", onSubmit, true);
    doc.removeEventListener("click", onClick, true);
    doc.removeEventListener("keydown", onKey, true);
  };
}
