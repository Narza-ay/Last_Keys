// WCAG 2.2 AA contrast of the colour tokens actually used for text
// (criterion V-U2): 4.5:1 for normal text, in the light and dark themes.

import css from "./tokens.css?raw";

function block(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  const open = css.indexOf("{", start + selector.length - 1);
  let depth = 0;
  let end = open;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    if (css[i] === "}" && --depth === 0) {
      end = i;
      break;
    }
  }
  const vars: Record<string, string> = {};
  for (const m of css.slice(open, end).matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) {
    if (m[1] && m[2]) vars[m[1]] = m[2].trim().replace(/\s+/g, " ");
  }
  return vars;
}

type Rgb = [number, number, number];

function parse(color: string, background?: Rgb): Rgb {
  const hex = /^#([0-9a-f]{6})$/i.exec(color);
  if (hex?.[1]) {
    const n = Number.parseInt(hex[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  const rgba = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(color);
  if (rgba && background) {
    const [r, g, b, a] = rgba.slice(1).map(Number) as [number, number, number, number];
    return [r * a + background[0] * (1 - a), g * a + background[1] * (1 - a), b * a + background[2] * (1 - a)];
  }
  throw new Error(`unsupported colour ${color}`);
}

function luminance([r, g, b]: Rgb): number {
  const f = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const light = block(":root {");
const dark = block(':root[data-theme="dark"]');
const systemDark = block(':root:not([data-theme="light"])');

// [text token, background token] pairs used for text in the interface.
const PAIRS: [string, string][] = [
  ["text", "bg"],
  ["text", "surface"],
  ["text", "sidebar"],
  ["text-2", "bg"],
  ["text-2", "surface"],
  ["text-2", "sidebar"],
  ["text-2", "surface-2"],
  ["text-3", "bg"],
  ["text-3", "surface"],
  ["text-3", "sidebar"],
  ["text-3", "surface-2"],
  ["accent-text", "accent"],
  ["accent", "surface"],
  ["accent", "bg"],
  ["danger", "surface"],
  ["danger", "danger-soft"],
  ["success", "success-soft"],
  ["warning", "warning-soft"],
  ["accent-soft-text", "accent-soft"],
];

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme", (_name, theme) => {
  it.each(PAIRS)("%s on %s reaches 4.5:1", (fg, bg) => {
    const surface = parse(theme.surface ?? "");
    const background = parse(theme[bg] ?? "", surface);
    const foreground = parse(theme[fg] ?? "", background);
    expect(contrast(foreground, background)).toBeGreaterThanOrEqual(4.5);
  });
});

it("the system dark theme and the chosen dark theme are identical", () => {
  expect(systemDark).toEqual(dark);
});
