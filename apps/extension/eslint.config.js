import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

// Letters in JSX text or in user-facing attributes mean untranslated text
// (criterion V-U1): every string shown to the user goes through t().
const LETTERS = "/[A-Za-zÀ-ÖØ-öø-ÿ]/";
const noHardCodedText = [
  "error",
  {
    selector: `JSXText[value=${LETTERS}]`,
    message: "Hard-coded UI text: use t() from src/popup/i18n.ts.",
  },
  {
    selector: `JSXAttribute[name.name=/^(placeholder|title|aria-label|alt|label|description)$/] > Literal[value=${LETTERS}]`,
    message: "Hard-coded UI text in an attribute: use t() from src/popup/i18n.ts.",
  },
];

export default tseslint.config(
  { ignores: ["dist", "node_modules", "test-results", "playwright-report"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.webextensions } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-restricted-syntax": noHardCodedText,
      "no-console": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Never inject HTML." },
        { property: "outerHTML", message: "Never inject HTML." },
        { property: "insertAdjacentHTML", message: "Never inject HTML." },
      ],
    },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "src/test/**"],
    rules: { "no-restricted-syntax": "off", "no-restricted-properties": "off" },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { ...globals.node } },
    rules: { "no-console": "off" },
  },
  {
    // Node.js script; functions passed to the browser use its globals.
    files: ["e2e/**/*.mjs"],
    languageOptions: { globals: { ...globals.node, ...globals.browser, ...globals.webextensions } },
    rules: { "no-console": "off" },
  },
);
