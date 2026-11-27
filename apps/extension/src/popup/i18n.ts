// Popup translations. English is the reference; the French catalogue must
// define the same keys and placeholders (i18n.test.ts). French spaces
// before « : ; ! ? » are made non-breaking, as in the desktop application.

const en = {
  "app.name": "Last Keys",
  "status.unavailable.title": "Last Keys is not reachable",
  "status.unavailable.text":
    "Open the Last Keys application on this computer and turn on “Allow the browser extension” in its settings.",
  "status.retry": "Try again",
  "status.unpaired.title": "Connect this browser",
  "status.unpaired.text":
    "The extension uses your vault through the Last Keys application. Nothing is stored in the browser.",
  "status.connect": "Connect",
  "status.refused.refused": "The connection was refused in Last Keys.",
  "status.refused.timeout": "The request was not answered in time.",
  "status.refused.busy": "Another connection request is waiting in Last Keys.",
  "status.refused.rate_limited": "Wait a moment before asking again.",
  "status.pairing.title": "Confirm in Last Keys",
  "status.pairing.text": "Check that the Last Keys window shows the same code, then click “Connect” there.",
  "status.locked.title": "Last Keys is locked",
  "status.locked.text": "Unlock it in the application. Your master password is never typed in the browser.",
  "status.unlock": "Unlock in Last Keys",
  "page.ineligible": "Last Keys does not fill this kind of page.",
  "page.idn": "International address: check that this is the site you expect.",
  "page.none": "No login saved for this site.",
  "page.noneHint": "Logins are offered only on the website they belong to.",
  "page.sameSite": "Same site",
  "detection.title": "Detect login forms on every site",
  "detection.text":
    "Lets Last Keys find login forms and offer to save the logins you submit. Without it, Last Keys works only on the page where you open it.",
  "detection.allow": "Allow",
  "login.fill": "Fill",
  "login.copyUsername": "Copy username",
  "login.copyPassword": "Copy password",
  "login.copyCode": "Copy code",
  "login.noUsername": "No username",
  "fill.none": "No field to fill was found on this page.",
  "fill.confirm.title": "Fill an embedded form?",
  "fill.confirm.text": "This form comes from {host}, inside the page you are on. Fill it only if you trust it.",
  "fill.confirm.yes": "Fill anyway",
  "fill.confirm.no": "Cancel",
  "copy.done": "Copied. The clipboard is cleared in {seconds} s.",
  "save.newTitle": "Save this login?",
  "save.updateTitle": "Update the password of “{title}”?",
  "save.pendingTitle": "Login submitted on {host}",
  "save.pendingText": "Unlock Last Keys to save it.",
  "save.save": "Save",
  "save.update": "Update",
  "save.notNow": "Not now",
  "save.done": "Saved in Last Keys.",
  "generate.title": "New password",
  "generate.button": "Generate a password",
  "generate.fill": "Fill",
  "generate.hint": "After you submit the form, Last Keys offers to save it.",
  "footer.open": "Open Last Keys",
  "error.generic": "Something went wrong. Try again.",
  "error.desktop_unavailable": "Last Keys is not reachable.",
  "error.locked": "Last Keys is locked.",
  "error.origin_mismatch": "This login does not belong to this website.",
  "error.ineligible_page": "Last Keys does not fill this kind of page.",
  "error.not_found": "This login no longer exists.",
  "error.unpaired": "This browser is not connected to Last Keys.",
  "error.timeout": "Last Keys did not answer in time.",
  "error.clipboard": "The clipboard is not available.",
};

export type Key = keyof typeof en;

const frRaw: Record<Key, string> = {
  "app.name": "Last Keys",
  "status.unavailable.title": "Last Keys est injoignable",
  "status.unavailable.text":
    "Ouvrez l’application Last Keys sur cet ordinateur et activez « Autoriser l’extension de navigateur » dans ses réglages.",
  "status.retry": "Réessayer",
  "status.unpaired.title": "Connecter ce navigateur",
  "status.unpaired.text":
    "L’extension utilise votre coffre par l’intermédiaire de l’application Last Keys. Rien n’est stocké dans le navigateur.",
  "status.connect": "Connecter",
  "status.refused.refused": "La connexion a été refusée dans Last Keys.",
  "status.refused.timeout": "La demande n’a pas reçu de réponse à temps.",
  "status.refused.busy": "Une autre demande de connexion attend dans Last Keys.",
  "status.refused.rate_limited": "Patientez un instant avant de redemander.",
  "status.pairing.title": "Confirmez dans Last Keys",
  "status.pairing.text": "Vérifiez que la fenêtre de Last Keys affiche le même code, puis cliquez sur « Connecter ».",
  "status.locked.title": "Last Keys est verrouillé",
  "status.locked.text":
    "Déverrouillez-le dans l’application. Votre mot de passe maître n’est jamais saisi dans le navigateur.",
  "status.unlock": "Déverrouiller dans Last Keys",
  "page.ineligible": "Last Keys ne remplit pas ce type de page.",
  "page.idn": "Adresse internationale : vérifiez qu’il s’agit bien du site attendu.",
  "page.none": "Aucun identifiant enregistré pour ce site.",
  "page.noneHint": "Les identifiants ne sont proposés que sur le site auquel ils appartiennent.",
  "page.sameSite": "Même site",
  "detection.title": "Détecter les formulaires sur tous les sites",
  "detection.text":
    "Permet à Last Keys de trouver les formulaires de connexion et de proposer d’enregistrer les identifiants que vous envoyez. Sans cela, Last Keys ne fonctionne que sur la page où vous l’ouvrez.",
  "detection.allow": "Autoriser",
  "login.fill": "Remplir",
  "login.copyUsername": "Copier l’identifiant",
  "login.copyPassword": "Copier le mot de passe",
  "login.copyCode": "Copier le code",
  "login.noUsername": "Pas d’identifiant",
  "fill.none": "Aucun champ à remplir n’a été trouvé sur cette page.",
  "fill.confirm.title": "Remplir un formulaire intégré ?",
  "fill.confirm.text":
    "Ce formulaire provient de {host}, à l’intérieur de la page affichée. Ne le remplissez que si vous lui faites confiance.",
  "fill.confirm.yes": "Remplir quand même",
  "fill.confirm.no": "Annuler",
  "copy.done": "Copié. Le presse-papiers sera vidé dans {seconds} s.",
  "save.newTitle": "Enregistrer cet identifiant ?",
  "save.updateTitle": "Mettre à jour le mot de passe de « {title} » ?",
  "save.pendingTitle": "Identifiant envoyé sur {host}",
  "save.pendingText": "Déverrouillez Last Keys pour l’enregistrer.",
  "save.save": "Enregistrer",
  "save.update": "Mettre à jour",
  "save.notNow": "Plus tard",
  "save.done": "Enregistré dans Last Keys.",
  "generate.title": "Nouveau mot de passe",
  "generate.button": "Générer un mot de passe",
  "generate.fill": "Remplir",
  "generate.hint": "Une fois le formulaire envoyé, Last Keys proposera de l’enregistrer.",
  "footer.open": "Ouvrir Last Keys",
  "error.generic": "Une erreur est survenue. Réessayez.",
  "error.desktop_unavailable": "Last Keys est injoignable.",
  "error.locked": "Last Keys est verrouillé.",
  "error.origin_mismatch": "Cet identifiant n’appartient pas à ce site.",
  "error.ineligible_page": "Last Keys ne remplit pas ce type de page.",
  "error.not_found": "Cet identifiant n’existe plus.",
  "error.unpaired": "Ce navigateur n’est pas connecté à Last Keys.",
  "error.timeout": "Last Keys n’a pas répondu à temps.",
  "error.clipboard": "Le presse-papiers n’est pas disponible.",
};

const typography = (text: string): string => text.replace(/ ([:;!?»])/g, " $1").replace(/« /g, "« ");

const fr = Object.fromEntries(Object.entries(frRaw).map(([k, v]) => [k, typography(v)])) as Record<Key, string>;

export const catalogues = { en, fr: frRaw } as const;
export type Locale = "en" | "fr";

export function localeOf(language: string): Locale {
  return language.toLowerCase().startsWith("fr") ? "fr" : "en";
}

export type Translate = (key: Key, vars?: Record<string, string | number>) => string;

export function translator(locale: Locale): Translate {
  const table: Record<Key, string> = locale === "fr" ? fr : en;
  return (key, vars) =>
    table[key].replace(/\{(\w+)\}/g, (match, name: string) => (vars && name in vars ? String(vars[name]) : match));
}

export function errorKey(code: string): Key {
  const key = `error.${code}`;
  return (key in en ? key : "error.generic") as Key;
}
